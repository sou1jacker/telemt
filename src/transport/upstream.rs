//! Upstream Management

use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use rand::Rng;
use tracing::{debug, warn, error, info};

use crate::config::{UpstreamConfig, UpstreamType};
use crate::error::{Result, ProxyError};
use crate::transport::socket::create_outgoing_socket_bound;
use crate::transport::socks::{connect_socks4, connect_socks5};

#[derive(Debug)]
struct UpstreamState {
    config: UpstreamConfig,
    healthy: bool,
    fails: u32,
    last_check: std::time::Instant,
}

#[derive(Clone)]
pub struct UpstreamManager {
    upstreams: Arc<RwLock<Vec<UpstreamState>>>,
}

impl UpstreamManager {
    pub fn new(configs: Vec<UpstreamConfig>) -> Self {
        let states = configs.into_iter()
            .filter(|c| c.enabled)
            .map(|c| UpstreamState {
                config: c,
                healthy: true, // Optimistic start
                fails: 0,
                last_check: std::time::Instant::now(),
            })
            .collect();
            
        Self {
            upstreams: Arc::new(RwLock::new(states)),
        }
    }
    
    /// Select an upstream using Weighted Round Robin (simplified)
    async fn select_upstream(&self) -> Option<usize> {
        let upstreams = self.upstreams.read().await;
        if upstreams.is_empty() {
            return None;
        }

        let healthy_indices: Vec<usize> = upstreams.iter()
            .enumerate()
            .filter(|(_, u)| u.healthy)
            .map(|(i, _)| i)
            .collect();
            
        if healthy_indices.is_empty() {
            // If all unhealthy, try any random one
            return Some(rand::thread_rng().gen_range(0..upstreams.len()));
        }
        
        // Weighted selection
        let total_weight: u32 = healthy_indices.iter()
            .map(|&i| upstreams[i].config.weight as u32)
            .sum();
            
        if total_weight == 0 {
            return Some(healthy_indices[rand::thread_rng().gen_range(0..healthy_indices.len())]);
        }
        
        let mut choice = rand::thread_rng().gen_range(0..total_weight);
        
        for &idx in &healthy_indices {
            let weight = upstreams[idx].config.weight as u32;
            if choice < weight {
                return Some(idx);
            }
            choice -= weight;
        }
        
        Some(healthy_indices[0])
    }
    
    pub async fn connect(&self, target: SocketAddr) -> Result<TcpStream> {
        let idx = self.select_upstream().await
            .ok_or_else(|| ProxyError::Config("No upstreams available".to_string()))?;
            
        let upstream = {
            let guard = self.upstreams.read().await;
            guard[idx].config.clone()
        };
        
        match self.connect_via_upstream(&upstream, target).await {
            Ok(stream) => {
                // Mark success
                let mut guard = self.upstreams.write().await;
                if let Some(u) = guard.get_mut(idx) {
                    if !u.healthy {
                        debug!("Upstream recovered: {:?}", u.config);
                    }
                    u.healthy = true;
                    u.fails = 0;
                }
                Ok(stream)
            },
            Err(e) => {
                // Mark failure
                let mut guard = self.upstreams.write().await;
                if let Some(u) = guard.get_mut(idx) {
                    u.fails += 1;
                    warn!("Failed to connect via upstream {:?}: {}. Fails: {}", u.config, e, u.fails);
                    if u.fails > 3 {
                        u.healthy = false;
                        warn!("Upstream disabled due to failures: {:?}", u.config);
                    }
                }
                Err(e)
            }
        }
    }
    
    async fn connect_via_upstream(&self, config: &UpstreamConfig, target: SocketAddr) -> Result<TcpStream> {
        match &config.upstream_type {
            UpstreamType::Direct { interface } => {
                let bind_ip = interface.as_ref()
                    .and_then(|s| s.parse::<IpAddr>().ok());
                
                let socket = create_outgoing_socket_bound(target, bind_ip)?;
                
                // Non-blocking connect logic
                socket.set_nonblocking(true)?;
                match socket.connect(&target.into()) {
                    Ok(()) => {},
                    Err(err) if err.raw_os_error() == Some(115) || err.kind() == std::io::ErrorKind::WouldBlock => {},
                    Err(err) => return Err(ProxyError::Io(err)),
                }
                
                let std_stream: std::net::TcpStream = socket.into();
                let stream = TcpStream::from_std(std_stream)?;
                
                // Wait for connection to complete
                stream.writable().await?;
                if let Some(e) = stream.take_error()? {
                    return Err(ProxyError::Io(e));
                }
                
                Ok(stream)
            },
            UpstreamType::Socks4 { address, interface, user_id } => {
                info!("Connecting to target {} via SOCKS4 proxy {}", target, address);
                
                let proxy_addr: SocketAddr = address.parse()
                    .map_err(|_| ProxyError::Config("Invalid SOCKS4 address".to_string()))?;
                    
                let bind_ip = interface.as_ref()
                    .and_then(|s| s.parse::<IpAddr>().ok());
                
                let socket = create_outgoing_socket_bound(proxy_addr, bind_ip)?;
                
                // Non-blocking connect logic
                socket.set_nonblocking(true)?;
                match socket.connect(&proxy_addr.into()) {
                    Ok(()) => {},
                    Err(err) if err.raw_os_error() == Some(115) || err.kind() == std::io::ErrorKind::WouldBlock => {},
                    Err(err) => return Err(ProxyError::Io(err)),
                }
                
                let std_stream: std::net::TcpStream = socket.into();
                let mut stream = TcpStream::from_std(std_stream)?;
                
                // Wait for connection to complete
                stream.writable().await?;
                if let Some(e) = stream.take_error()? {
                    return Err(ProxyError::Io(e));
                }
                
                connect_socks4(&mut stream, target, user_id.as_deref()).await?;
                Ok(stream)
            },
            UpstreamType::Socks5 { address, interface, username, password } => {
                info!("Connecting to target {} via SOCKS5 proxy {}", target, address);
                
                let proxy_addr: SocketAddr = address.parse()
                    .map_err(|_| ProxyError::Config("Invalid SOCKS5 address".to_string()))?;
                    
                let bind_ip = interface.as_ref()
                    .and_then(|s| s.parse::<IpAddr>().ok());
                
                let socket = create_outgoing_socket_bound(proxy_addr, bind_ip)?;
                
                // Non-blocking connect logic
                socket.set_nonblocking(true)?;
                match socket.connect(&proxy_addr.into()) {
                    Ok(()) => {},
                    Err(err) if err.raw_os_error() == Some(115) || err.kind() == std::io::ErrorKind::WouldBlock => {},
                    Err(err) => return Err(ProxyError::Io(err)),
                }
                
                let std_stream: std::net::TcpStream = socket.into();
                let mut stream = TcpStream::from_std(std_stream)?;
                
                // Wait for connection to complete
                stream.writable().await?;
                if let Some(e) = stream.take_error()? {
                    return Err(ProxyError::Io(e));
                }
                
                connect_socks5(&mut stream, target, username.as_deref(), password.as_deref()).await?;
                Ok(stream)
            },
        }
    }
    
    /// Background task to check health
    pub async fn run_health_checks(&self) {
        // Simple TCP connect check to a known stable DC (e.g. 149.154.167.50:443 - DC2)
        let check_target: SocketAddr = "149.154.167.50:443".parse().unwrap();
        
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            
            let count = self.upstreams.read().await.len();
            for i in 0..count {
                let config = {
                    let guard = self.upstreams.read().await;
                    guard[i].config.clone()
                };
                
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    self.connect_via_upstream(&config, check_target)
                ).await;
                
                let mut guard = self.upstreams.write().await;
                let u = &mut guard[i];
                
                match result {
                    Ok(Ok(_stream)) => {
                        if !u.healthy {
                            debug!("Upstream recovered: {:?}", u.config);
                        }
                        u.healthy = true;
                        u.fails = 0;
                    }
                    Ok(Err(e)) => {
                        debug!("Health check failed for {:?}: {}", u.config, e);
                        // Don't mark unhealthy immediately in background check
                    }
                    Err(_) => {
                        debug!("Health check timeout for {:?}", u.config);
                    }
                }
                u.last_check = std::time::Instant::now();
            }
        }
    }
}
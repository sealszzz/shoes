//! UoT server-side execution helpers.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::address::NetLocation;
use crate::anytls::AnyTlsStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::resolver::Resolver;
use crate::routing::{run_udp_routing, ServerStream};
use crate::tcp::tcp_server::run_udp_copy;
use crate::uot::UotV1ServerStream;
use crate::vless::VlessMessageStream;

pub async fn run_uot_v2_connect(
    stream: AnyTlsStream,
    destination: NetLocation,
    proxy_provider: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    connect_timeout: Duration,
) -> io::Result<()> {
    let action = match tokio::time::timeout(
        connect_timeout,
        proxy_provider.judge(destination.clone().into(), &resolver),
    )
    .await
    {
        Ok(Ok(action)) => action,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("UDP route decision timed out after {:?}", connect_timeout),
            ));
        }
    };

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let server_stream: Box<dyn AsyncMessageStream> =
                Box::new(VlessMessageStream::new(stream));

            let client_stream = match tokio::time::timeout(
                connect_timeout,
                chain_group.connect_udp_bidirectional(&resolver, remote_location),
            )
            .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("UDP connect timed out after {:?}", connect_timeout),
                    ));
                }
            };

            run_udp_copy(server_stream, client_stream, false, false).await
        }
        ConnectDecision::Block => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "UDP blocked by rules",
        )),
    }
}

pub async fn run_uot_multi_destination(
    stream: AnyTlsStream,
    proxy_provider: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()> {
    let server_stream: Box<dyn AsyncTargetedMessageStream> =
        Box::new(UotV1ServerStream::new(stream));

    run_udp_routing(
        ServerStream::Targeted(server_stream),
        proxy_provider,
        resolver,
        false,
    )
    .await
}

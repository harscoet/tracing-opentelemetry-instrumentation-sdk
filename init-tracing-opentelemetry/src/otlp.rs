use std::collections::HashMap;
use std::str::FromStr;

use http::{HeaderName, HeaderValue};
use opentelemetry::sdk::trace::{Sampler, Tracer};
use opentelemetry::sdk::Resource;
use opentelemetry::trace::TraceError;
use opentelemetry_otlp::SpanExporterBuilder;
use tonic::metadata::MetadataMap;
#[cfg(feature = "tls")]
use tonic::transport::ClientTlsConfig;

#[must_use]
pub fn identity(v: opentelemetry_otlp::OtlpTracePipeline) -> opentelemetry_otlp::OtlpTracePipeline {
    v
}

// see https://opentelemetry.io/docs/reference/specification/protocol/exporter/
pub fn init_tracer<F>(resource: Resource, transform: F) -> Result<Tracer, TraceError>
where
    F: FnOnce(opentelemetry_otlp::OtlpTracePipeline) -> opentelemetry_otlp::OtlpTracePipeline,
{
    use opentelemetry_otlp::WithExportConfig;

    let (maybe_protocol, maybe_endpoint) = read_protocol_and_endpoint_from_env();
    let (protocol, endpoint) =
        infer_protocol_and_endpoint(maybe_protocol.as_deref(), maybe_endpoint.as_deref());
    tracing::debug!(target: "otel::setup", OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = endpoint);
    tracing::debug!(target: "otel::setup", OTEL_EXPORTER_OTLP_TRACES_PROTOCOL = protocol);
    let exporter: SpanExporterBuilder = match protocol.as_str() {
        "http/protobuf" => opentelemetry_otlp::new_exporter()
            .http()
            .with_endpoint(endpoint)
            .with_headers(read_http_headers_from_env())
            .into(),
        #[cfg(feature = "tls")]
        "grpc/tls" => opentelemetry_otlp::new_exporter()
            .tonic()
            .with_tls_config(ClientTlsConfig::new())
            .with_endpoint(endpoint)
            .with_metadata(read_tonic_metadata_from_env())
            .into(),
        _ => opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint)
            .with_metadata(read_tonic_metadata_from_env())
            .into(),
    };

    let mut pipeline = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            opentelemetry::sdk::trace::config()
                .with_resource(resource)
                .with_sampler(read_sampler_from_env()),
        );
    pipeline = transform(pipeline);
    pipeline.install_batch(opentelemetry::runtime::Tokio)
}

fn read_protocol_and_endpoint_from_env() -> (Option<String>, Option<String>) {
    let maybe_endpoint = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT"))
        .ok();
    let maybe_protocol = std::env::var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
        .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL"))
        .ok();
    (maybe_protocol, maybe_endpoint)
}

/// see <https://opentelemetry.io/docs/reference/specification/sdk-environment-variables/#general-sdk-configuration>
/// TODO log error and infered sampler
fn read_sampler_from_env() -> Sampler {
    let mut name = std::env::var("OTEL_TRACES_SAMPLER")
        .ok()
        .unwrap_or_default()
        .to_lowercase();
    let v = match name.as_str() {
        "always_on" => Sampler::AlwaysOn,
        "always_off" => Sampler::AlwaysOff,
        "traceidratio" => Sampler::TraceIdRatioBased(read_sampler_arg_from_env(1f64)),
        "parentbased_always_on" => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
        "parentbased_always_off" => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
        "parentbased_traceidratio" => Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            read_sampler_arg_from_env(1f64),
        ))),
        "jaeger_remote" => todo!("unsupported: OTEL_TRACES_SAMPLER='jaeger_remote'"),
        "xray" => todo!("unsupported: OTEL_TRACES_SAMPLER='xray'"),
        _ => {
            name = "parentbased_always_on".to_string();
            Sampler::ParentBased(Box::new(Sampler::AlwaysOn))
        }
    };
    tracing::debug!(target: "otel::setup", OTEL_TRACES_SAMPLER = ?name);
    v
}

fn read_sampler_arg_from_env<T>(default: T) -> T
where
    T: FromStr + Copy + std::fmt::Debug,
{
    //TODO Log for invalid value (how to log)
    let v = std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .map_or(default, |s| T::from_str(&s).unwrap_or(default));
    tracing::debug!(target: "otel::setup", OTEL_TRACES_SAMPLER_ARG = ?v);
    v
}

fn read_raw_headers_from_env() -> Option<String> {
    std::env::var("OTEL_EXPORTER_OTLP_TRACES_HEADERS")
        .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_HEADERS"))
        .ok()
}

fn read_http_headers_from_env() -> HashMap<String, String> {
    read_raw_headers_from_env()
        .map(|raw_headers| {
            raw_headers_to_key_value_iter(&raw_headers)
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn read_tonic_metadata_from_env() -> MetadataMap {
    read_raw_headers_from_env()
        .map(|raw_headers| {
            MetadataMap::from_headers(
                raw_headers_to_key_value_iter(&raw_headers)
                    .filter_map(|(key, value)| {
                        Some((
                            HeaderName::from_str(key).ok()?,
                            HeaderValue::from_str(value).ok()?,
                        ))
                    })
                    .collect(),
            )
        })
        .unwrap_or_default()
}

fn raw_headers_to_key_value_iter(value: &str) -> impl Iterator<Item = (&str, &str)> {
    value
        .split_terminator(',')
        .map(str::trim)
        .filter_map(|pair| {
            if pair.is_empty() {
                None
            } else {
                pair.split_once('=')
                    .map(|(key, value)| (key.trim(), value.trim()))
                    .filter(|(key, value)| !key.is_empty() && !value.is_empty())
            }
        })
}

fn infer_protocol_and_endpoint(
    maybe_protocol: Option<&str>,
    maybe_endpoint: Option<&str>,
) -> (String, String) {
    #[cfg_attr(not(feature = "tls"), allow(unused_mut))]
    let mut protocol = maybe_protocol.unwrap_or_else(|| {
        if maybe_endpoint.map_or(false, |e| e.contains(":4317")) {
            "grpc"
        } else {
            "http/protobuf"
        }
    });

    #[cfg(feature = "tls")]
    if protocol == "grpc" && maybe_endpoint.unwrap_or("").starts_with("https") {
        protocol = "grpc/tls";
    }

    let endpoint = match protocol {
        "http/protobuf" => maybe_endpoint.unwrap_or("http://localhost:4318"), //Devskim: ignore DS137138
        _ => maybe_endpoint.unwrap_or("http://localhost:4317"), //Devskim: ignore DS137138
    };

    (protocol.to_string(), endpoint.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::assert;
    use rstest::rstest;

    #[rstest]
    #[case(None, None, "http/protobuf", "http://localhost:4318")] //Devskim: ignore DS137138
    #[case(Some("http/protobuf"), None, "http/protobuf", "http://localhost:4318")] //Devskim: ignore DS137138
    #[case(Some("grpc"), None, "grpc", "http://localhost:4317")] //Devskim: ignore DS137138
    #[case(None, Some("http://localhost:4317"), "grpc", "http://localhost:4317")] //Devskim: ignore DS137138
    #[cfg_attr(feature = "tls", case(
        None,
        Some("https://localhost:4317"),
        "grpc/tls",
        "https://localhost:4317"
    ))]
    #[cfg_attr(feature = "tls", case(
        Some("grpc/tls"),
        Some("https://localhost:4317"),
        "grpc/tls",
        "https://localhost:4317"
    ))]
    #[case(
        Some("http/protobuf"),
        Some("http://localhost:4318"), //Devskim: ignore DS137138
        "http/protobuf",
        "http://localhost:4318" //Devskim: ignore DS137138
    )]
    #[case(
        Some("http/protobuf"),
        Some("https://examples.com:4318"),
        "http/protobuf",
        "https://examples.com:4318"
    )]
    #[case(
        Some("http/protobuf"),
        Some("https://examples.com:4317"),
        "http/protobuf",
        "https://examples.com:4317"
    )]
    fn test_infer_protocol_and_endpoint(
        #[case] traces_protocol: Option<&str>,
        #[case] traces_endpoint: Option<&str>,
        #[case] expected_protocol: &str,
        #[case] expected_endpoint: &str,
    ) {
        assert!(
            infer_protocol_and_endpoint(traces_protocol, traces_endpoint)
                == (expected_protocol.to_string(), expected_endpoint.to_string())
        );
    }

    #[rstest]
    #[case(
        "k3=val=10,22,34,k4=,k5=10",
        vec![("k3", "val=10"), ("k5", "10")]
    )]
    #[case(
        "",
        vec![]
    )]
    #[case(
        "k1=foo,  k2 = bar, ,=, k3=1",
        vec![("k1", "foo"), ("k2", "bar"), ("k3", "1")]
    )]
    fn test_raw_headers_to_key_value_iter(
        #[case] raw_headers: &str,
        #[case] expected_key_values: Vec<(&str, &str)>,
    ) {
        assert_eq!(
            raw_headers_to_key_value_iter(raw_headers).collect::<Vec<_>>(),
            expected_key_values
        );
    }

    #[rstest]
    #[case(
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
        Some("k1=foo,k2=bar"),
        vec![("k1", "foo"), ("k2", "bar")]
    )]
    #[case(
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
        Some(""),
        vec![]
    )]
    #[case(
        "OTEL_EXPORTER_OTLP_HEADERS",
        Some("k1=foo,k2=bar"),
        vec![("k1", "foo"), ("k2", "bar")]
    )]
    #[case(
        "OTEL_EXPORTER_OTLP_HEADERS",
        None,
        vec![]
    )]
    #[case(
        "WRONG_ENV_VAR_NAME",
        Some("k1=foo,k2=bar"),
        vec![]
    )]
    fn test_read_http_headers_from_env(
        #[case] env_var_name: &str,
        #[case] env_var_value: Option<&str>,
        #[case] expected_key_values: Vec<(&str, &str)>,
    ) {
        temp_env::with_var(env_var_name, env_var_value, || {
            assert_eq!(
                read_http_headers_from_env(),
                expected_key_values
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            );
        });
    }
}

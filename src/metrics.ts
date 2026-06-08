import {
  Counter,
  Gauge,
  Histogram,
  Registry,
  collectDefaultMetrics,
  type CounterConfiguration,
  type GaugeConfiguration,
  type HistogramConfiguration,
} from "prom-client";

export type { Counter, Gauge, Histogram, Registry } from "prom-client";

export type InvokeOutcome =
  | "success"
  | "scope_not_found"
  | "malformed_request"
  | "verification_failed"
  | "config_not_found"
  | "config_subject_mismatch"
  | "config_instance_required"
  | "invalid_output"
  | "handler_error";

export type FileDownloadOutcome = "success" | "not_found";

type HttpLabels = "method" | "route" | "status";
type InvokeLabels = "scope" | "outcome";
type InvokeDurationLabels = "scope";
type FileDownloadLabels = "outcome";

export class ModuleMetrics {
  readonly registry: Registry;

  private readonly httpRequestsTotal: Counter<HttpLabels>;
  private readonly httpRequestDuration: Histogram<HttpLabels>;
  private readonly invokeTotal: Counter<InvokeLabels>;
  private readonly invokeDuration: Histogram<InvokeDurationLabels>;
  private readonly fileDownloadsTotal: Counter<FileDownloadLabels>;

  constructor(moduleId: string) {
    this.registry = new Registry();
    this.registry.setDefaultLabels({ module_id: moduleId });

    collectDefaultMetrics({ register: this.registry, prefix: "huglo_module_" });

    this.httpRequestsTotal = new Counter({
      name: "huglo_module_http_requests_total",
      help: "Total HTTP requests handled by the module server",
      labelNames: ["method", "route", "status"],
      registers: [this.registry],
    });

    this.httpRequestDuration = new Histogram({
      name: "huglo_module_http_request_duration_seconds",
      help: "HTTP request duration in seconds",
      labelNames: ["method", "route", "status"],
      registers: [this.registry],
    });

    this.invokeTotal = new Counter({
      name: "huglo_module_invoke_total",
      help: "Total invoke requests by scope and outcome",
      labelNames: ["scope", "outcome"],
      registers: [this.registry],
    });

    this.invokeDuration = new Histogram({
      name: "huglo_module_invoke_duration_seconds",
      help: "Invoke handler duration in seconds",
      labelNames: ["scope"],
      registers: [this.registry],
    });

    this.fileDownloadsTotal = new Counter({
      name: "huglo_module_file_downloads_total",
      help: "Total file download requests by outcome",
      labelNames: ["outcome"],
      registers: [this.registry],
    });
  }

  counter<T extends string>(
    config: Omit<CounterConfiguration<T>, "registers">,
  ): Counter<T> {
    return new Counter({ ...config, registers: [this.registry] });
  }

  gauge<T extends string>(
    config: Omit<GaugeConfiguration<T>, "registers">,
  ): Gauge<T> {
    return new Gauge({ ...config, registers: [this.registry] });
  }

  histogram<T extends string>(
    config: Omit<HistogramConfiguration<T>, "registers">,
  ): Histogram<T> {
    return new Histogram({ ...config, registers: [this.registry] });
  }

  recordHttpRequest(
    method: string,
    route: string,
    status: string,
    durationSeconds: number,
  ): void {
    const labels = { method, route, status };
    this.httpRequestsTotal.inc(labels);
    this.httpRequestDuration.observe(labels, durationSeconds);
  }

  recordInvoke(scope: string, outcome: InvokeOutcome): void {
    this.invokeTotal.inc({ scope, outcome });
  }

  startInvokeTimer(scope: string): () => void {
    const end = this.invokeDuration.startTimer({ scope });
    return () => {
      end();
    };
  }

  recordFileDownload(outcome: FileDownloadOutcome): void {
    this.fileDownloadsTotal.inc({ outcome });
  }
}

export function createModuleMetrics(moduleId: string): ModuleMetrics {
  return new ModuleMetrics(moduleId);
}

import { describe, it, expect } from "vitest";
import { FlowNodeContextSchema } from "../src/flow-node-context.js";

describe("FlowNodeContextSchema", () => {
  it("parses context with all fields", () => {
    expect(
      FlowNodeContextSchema.parse({
        flowId: "flow-1",
        nodeId: "node-1",
        configInstanceId: "inst-abc",
      }),
    ).toEqual({
      flowId: "flow-1",
      nodeId: "node-1",
      configInstanceId: "inst-abc",
    });
  });

  it("parses context without configInstanceId", () => {
    expect(
      FlowNodeContextSchema.parse({
        flowId: "flow-1",
        nodeId: "node-1",
      }),
    ).toEqual({
      flowId: "flow-1",
      nodeId: "node-1",
    });
  });

  it("rejects empty flowId", () => {
    expect(() =>
      FlowNodeContextSchema.parse({
        flowId: "",
        nodeId: "node-1",
      }),
    ).toThrow();
  });

  it("rejects empty nodeId", () => {
    expect(() =>
      FlowNodeContextSchema.parse({
        flowId: "flow-1",
        nodeId: "",
      }),
    ).toThrow();
  });
});

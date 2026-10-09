import { describe, it, expect } from "vitest";
import { parseHugloSubject } from "../src/huglo-subject.js";

describe("parseHugloSubject", () => {
  it("accepts valid user and agent subjects", () => {
    expect(parseHugloSubject("huglo:user:abc123")).toEqual({
      namespace: "user",
      id: "abc123",
      subject: "huglo:user:abc123",
    });
    expect(parseHugloSubject("huglo:agent:agt_1")).toEqual({
      namespace: "agent",
      id: "agt_1",
      subject: "huglo:agent:agt_1",
    });
    expect(parseHugloSubject("huglo:proj1:entity-1").namespace).toBe("proj1");
  });

  it("rejects namespace too short", () => {
    expect(() => parseHugloSubject("huglo:usr:abc")).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
  });

  it("rejects namespace too long", () => {
    expect(() => parseHugloSubject("huglo:abcdefghijklmnopq:abc")).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
  });

  it("rejects uppercase namespace", () => {
    expect(() => parseHugloSubject("huglo:User:abc")).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
  });

  it("accepts userx namespace in the parser (grant author check enforces user)", () => {
    expect(parseHugloSubject("huglo:userx:abc").namespace).toBe("userx");
  });

  it("accepts id up to 256 characters", () => {
    const id = "a".repeat(256);
    expect(parseHugloSubject(`huglo:user:${id}`).id).toBe(id);
  });

  it("rejects id longer than 256 characters", () => {
    const id = "a".repeat(257);
    expect(() => parseHugloSubject(`huglo:user:${id}`)).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
  });

  it("rejects ids containing whitespace", () => {
    for (const id of ["has space", "has\ttab", "has\nline"]) {
      expect(() => parseHugloSubject(`huglo:user:${id}`)).toThrow(
        expect.objectContaining({ code: "invalid_subject" }),
      );
    }
  });

  it("rejects missing or empty id", () => {
    expect(() => parseHugloSubject("huglo:user:")).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
    expect(() => parseHugloSubject("huglo:user")).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
  });

  it("rejects extra colons in id segment", () => {
    expect(() => parseHugloSubject("huglo:user:abc:extra")).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
  });

  it("rejects bare ids without huglo prefix", () => {
    expect(() => parseHugloSubject("user:abc")).toThrow(
      expect.objectContaining({ code: "invalid_subject" }),
    );
  });
});

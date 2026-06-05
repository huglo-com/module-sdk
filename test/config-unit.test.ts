import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  assembleConfigValues,
  ConfigAssemblyError,
  formatInstanceLabel,
  truncateInstanceId,
} from "../src/config.js";

describe("config unit", () => {
  describe("assembleConfigValues", () => {
    it("throws when locked field has no lockedValues entry and no schema default", () => {
      const schema = z.object({ locked: z.string() });
      expect(() =>
        assembleConfigValues({
          definition: {
            schema,
            fields: { locked: "locked" },
          },
          userValues: {},
          hostValues: {},
        }),
      ).toThrow(/Locked field 'locked'/);
    });

    it("throws when userEntered field is missing", () => {
      expect(() =>
        assembleConfigValues({
          definition: {
            schema: z.object({ label: z.string() }),
            fields: { label: "userEntered" },
          },
          userValues: {},
          hostValues: {},
        }),
      ).toThrow(ConfigAssemblyError);
    });

    it("defaults field source to userEntered when omitted from fields map", () => {
      const result = assembleConfigValues({
        definition: {
          schema: z.object({ optional: z.string().optional() }),
          fields: {},
        },
        userValues: { optional: "from-user" },
        hostValues: {},
      });
      expect(result.values.optional).toBe("from-user");
    });
  });

  describe("truncateInstanceId", () => {
    it("truncates long ids with ellipsis", () => {
      expect(truncateInstanceId("inst-abcdefghij")).toBe("inst-abc…");
    });
  });

  describe("formatInstanceLabel", () => {
    const fields = [{ name: "label", type: { type: "string" }, source: "userEntered" as const }];

    it("falls back to truncated id when first field is non-string", () => {
      expect(formatInstanceLabel({ label: 42 }, "instance-xyz", fields)).toBe("instance…");
    });

    it("falls back to truncated id when fields array is empty", () => {
      expect(formatInstanceLabel({}, "instance-xyz", [])).toBe("instance…");
    });
  });

  it("ConfigAssemblyError has correct name", () => {
    const err = new ConfigAssemblyError("test");
    expect(err.name).toBe("ConfigAssemblyError");
  });
});

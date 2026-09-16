import { describe, it, expect } from "vitest";
import { sanitizeText } from "../sanitize.js";

// Invisible/control codepoints are written as \u / \x escapes on purpose — a literal
// zero-width or bidi char in source is unverifiable and U+2028/2029 can break the file.

describe("sanitizeText — hidden/control unicode strip", () => {
  it("strips a zero-width space and reports it (count + kind)", () => {
    const { text, report } = sanitizeText("drop\u200bsponsors");
    expect(text).toBe("dropsponsors");
    expect(report.removed).toBe(1);
    expect(report.kinds).toEqual(["zero-width-space"]);
  });

  it("strips bidi override controls (RLO/PDF family)", () => {
    const { text, report } = sanitizeText("a\u202eb\u202cc");
    expect(text).toBe("abc");
    expect(report.removed).toBe(2);
    expect(report.kinds).toEqual(["bidi-override"]);
  });

  it("strips Unicode Tags-block chars (astral hidden-prompt vector)", () => {
    const { text, report } = sanitizeText("hi\u{E0041}\u{E0042}");
    expect(text).toBe("hi");
    expect(report.removed).toBe(2);
    expect(report.kinds).toEqual(["tag-char"]);
  });

  it("strips C0/C1 controls but KEEPS newline and tab", () => {
    const { text, report } = sanitizeText("a\x00b\x7fc\td\ne");
    expect(text).toBe("abc\td\ne");
    expect(report.removed).toBe(2);
    expect(report.kinds).toEqual(["control-char"]);
  });

  it("normalizes CRLF/lone-CR to LF without counting \\r as stripped", () => {
    const { text, report } = sanitizeText("line1\r\nline2\rline3");
    expect(text).toBe("line1\nline2\nline3");
    expect(report.removed).toBe(0);
    expect(report.kinds).toEqual([]);
  });

  it("strips a soft hyphen via the Cf-format long tail", () => {
    const { text, report } = sanitizeText("co\u00adoperate");
    expect(text).toBe("cooperate");
    expect(report.removed).toBe(1);
    expect(report.kinds).toEqual(["format-char"]);
  });

  it("leaves legitimate visible unicode (accents, CJK, emoji) untouched", () => {
    const clean = "café 日本語 🚀 résumé";
    const { text, report } = sanitizeText(clean);
    expect(text).toBe(clean);
    expect(report.removed).toBe(0);
    expect(report.kinds).toEqual([]);
  });

  it("returns sorted, unique kind labels across a mixed payload", () => {
    const { report } = sanitizeText("x\u200b\u202e\u200c\x01");
    expect(report.removed).toBe(4);
    expect(report.kinds).toEqual(["bidi-override", "control-char", "zero-width-space"]);
  });
});

import { describe, it, expect, beforeEach } from "vitest";
import { CredentialStore } from "./credential-store.js";
import type { CredentialType } from "@lobsec/shared";

describe("CredentialStore", () => {
  let store: CredentialStore;
  const accessLog: Array<{ label: string; type: CredentialType; op: string }> = [];

  beforeEach(() => {
    accessLog.length = 0;
    store = new CredentialStore((label, type, op) => {
      accessLog.push({ label, type, op });
    });
  });

  describe("load and get", () => {
    it("loads and retrieves a credential", () => {
      store.load("api-key", "llm-api-key", "sk-test-123");
      expect(store.get("api-key")).toBe("sk-test-123");
    });

    it("returns undefined for unknown label", () => {
      expect(store.get("nonexistent")).toBeUndefined();
    });

    it("loads from env var", () => {
      process.env["TEST_LOBSEC_KEY"] = "test-value";
      const ok = store.loadFromEnv("env-key", "channel-token", "TEST_LOBSEC_KEY");
      expect(ok).toBe(true);
      expect(store.get("env-key")).toBe("test-value");
      delete process.env["TEST_LOBSEC_KEY"];
    });

    it("returns false for missing env var", () => {
      const ok = store.loadFromEnv("missing", "channel-token", "NONEXISTENT_VAR_123");
      expect(ok).toBe(false);
    });

    it("returns false for empty env var", () => {
      process.env["TEST_EMPTY"] = "";
      const ok = store.loadFromEnv("empty", "channel-token", "TEST_EMPTY");
      expect(ok).toBe(false);
      delete process.env["TEST_EMPTY"];
    });
  });

  describe("has", () => {
    it("returns true for loaded credential", () => {
      store.load("key", "llm-api-key", "value");
      expect(store.has("key")).toBe(true);
    });

    it("returns false for missing credential", () => {
      expect(store.has("missing")).toBe(false);
    });
  });

  describe("metadata", () => {
    it("tracks access count", () => {
      store.load("key", "llm-api-key", "value");
      store.get("key");
      store.get("key");
      store.get("key");

      const meta = store.getMeta("key");
      expect(meta?.accessCount).toBe(3);
      expect(meta?.lastAccessedAt).toBeDefined();
    });

    it("records loadedAt timestamp", () => {
      store.load("key", "llm-api-key", "value");
      const meta = store.getMeta("key");
      expect(meta?.loadedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it("returns undefined meta for unknown label", () => {
      expect(store.getMeta("missing")).toBeUndefined();
    });
  });

  describe("list", () => {
    it("lists all credentials", () => {
      store.load("a", "llm-api-key", "val-a");
      store.load("b", "channel-token", "val-b");
      const entries = store.list();
      expect(entries).toHaveLength(2);
      expect(entries.map((e) => e.label).sort()).toEqual(["a", "b"]);
    });

    it("does not expose values in list", () => {
      store.load("secret", "llm-api-key", "super-secret-value");
      const entries = store.list();
      const json = JSON.stringify(entries);
      expect(json).not.toContain("super-secret-value");
    });
  });

  describe("delete", () => {
    it("removes a credential", () => {
      store.load("key", "llm-api-key", "value");
      expect(store.delete("key")).toBe(true);
      expect(store.has("key")).toBe(false);
      expect(store.get("key")).toBeUndefined();
    });

    it("returns false for unknown label", () => {
      expect(store.delete("missing")).toBe(false);
    });

    it("logs destroy operation", () => {
      store.load("key", "llm-api-key", "value");
      store.delete("key");
      expect(accessLog).toContainEqual({
        label: "key",
        type: "llm-api-key",
        op: "destroy",
      });
    });
  });

  describe("destroy", () => {
    it("clears all credentials", () => {
      store.load("a", "llm-api-key", "val-a");
      store.load("b", "channel-token", "val-b");
      store.destroy();

      expect(store.size).toBe(0);
      expect(store.isDestroyed).toBe(true);
      expect(store.get("a")).toBeUndefined();
      expect(store.get("b")).toBeUndefined();
    });

    it("prevents further loads after destroy", () => {
      store.destroy();
      store.load("key", "llm-api-key", "value");
      expect(store.has("key")).toBe(false);
    });

    it("prevents env loads after destroy", () => {
      store.destroy();
      process.env["TEST_DESTROYED"] = "value";
      const ok = store.loadFromEnv("key", "llm-api-key", "TEST_DESTROYED");
      expect(ok).toBe(false);
      delete process.env["TEST_DESTROYED"];
    });

    it("logs destroy for each credential", () => {
      store.load("a", "llm-api-key", "val-a");
      store.load("b", "channel-token", "val-b");
      store.destroy();

      const destroyOps = accessLog.filter((e) => e.op === "destroy");
      expect(destroyOps).toHaveLength(2);
    });
  });

  describe("access logging", () => {
    it("logs retrieve operations", () => {
      store.load("key", "llm-api-key", "value");
      store.get("key");
      expect(accessLog).toContainEqual({
        label: "key",
        type: "llm-api-key",
        op: "retrieve",
      });
    });

    it("does not log value in callback", () => {
      store.load("secret", "llm-api-key", "super-secret");
      store.get("secret");
      const logStr = JSON.stringify(accessLog);
      expect(logStr).not.toContain("super-secret");
    });
  });

  describe("size", () => {
    it("reflects loaded credentials count", () => {
      expect(store.size).toBe(0);
      store.load("a", "llm-api-key", "val");
      expect(store.size).toBe(1);
      store.load("b", "channel-token", "val");
      expect(store.size).toBe(2);
      store.delete("a");
      expect(store.size).toBe(1);
    });
  });
});

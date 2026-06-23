import { Hono } from "hono";
import type { Env } from "../env.js";

export type SkillInfo = {
  id: string;
  cmd: string; // includes the leading '/'
  label: string;
  description?: string;
  icon?: string;
};

const skills = new Hono<{ Bindings: Env; Variables: { userId: string } }>();

/** GET /api/skills — list available OpenClaw skills (fetched from plugin via DO) */
skills.get("/", async (c) => {
  const userId = c.get("userId");
  const doId = c.env.CONNECTION_DO.idFromName(userId);
  const stub = c.env.CONNECTION_DO.get(doId);
  const res = await stub.fetch(new Request("https://internal/skills"));
  const data = await res.json<{ skills: SkillInfo[] }>();
  return c.json(data);
});

export { skills };

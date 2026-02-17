#!/usr/bin/env node

import { Command } from "commander";
import { initCommand } from "./commands/init.js";
import { startCommand } from "./commands/start.js";
import { stopCommand } from "./commands/stop.js";
import { statusCommand } from "./commands/status.js";
import { logsCommand } from "./commands/logs.js";

const program = new Command();

program
  .name("lobsec")
  .description("Security hardening wrapper for OpenClaw")
  .version("0.1.0")
  .option("--json", "Output in JSON format")
  .option("--verbose", "Enable verbose logging");

program.addCommand(initCommand());
program.addCommand(startCommand());
program.addCommand(stopCommand());
program.addCommand(statusCommand());
program.addCommand(logsCommand());

program.parse();

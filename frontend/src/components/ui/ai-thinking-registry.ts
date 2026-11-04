import {
  Bot, FileDiff as FileDiffIcon, FilePen, FilePlus2, FileText, FolderSearch,
  Globe, ListChecks, Plug, Search, Terminal,
} from "lucide-react";
import type { ToolDefinition } from "./ai-thinking-and-tool-calls";

export const DEFAULT_TOOL_REGISTRY: Record<string, ToolDefinition> = {
  exec: { name: "exec", label: "Run", icon: Terminal },
  execute_command: { name: "execute_command", label: "Run", icon: Terminal },
  read: { name: "read", label: "Read", icon: FileText },
  read_file: { name: "read_file", label: "Read", icon: FileText },
  write: { name: "write", label: "Write", icon: FilePlus2 },
  write_file: { name: "write_file", label: "Write", icon: FilePlus2 },
  edit: { name: "edit", label: "Edit", icon: FilePen },
  edit_file: { name: "edit_file", label: "Edit", icon: FilePen },
  patch: { name: "patch", label: "Patch", icon: FileDiffIcon },
  search: { name: "search", label: "Search", icon: Search },
  search_web: { name: "search_web", label: "Search", icon: Search },
  glob: { name: "glob", label: "Glob", icon: FolderSearch },
  fetch: { name: "fetch", label: "Fetch", icon: Globe },
  web: { name: "web", label: "Web", icon: Globe },
  todo: { name: "todo", label: "Todo", icon: ListChecks },
  mcp: { name: "mcp", label: "MCP", icon: Plug },
  agent: { name: "agent", label: "Agent", icon: Bot },
  task: { name: "task", label: "Agent", icon: Bot },
};

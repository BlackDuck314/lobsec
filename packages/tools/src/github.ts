// ── GitHub REST API Tools ────────────────────────────────────────────────────
// Interact with GitHub repos, issues, and PRs via REST API.
// PAT from environment (injected by HSM extraction).

export interface GitHubConfig {
  pat: string;
  user: string;
}

interface GitHubRepo {
  full_name: string;
  description: string | null;
  private: boolean;
  language: string | null;
  stargazers_count: number;
  updated_at: string;
  html_url: string;
}

interface GitHubIssue {
  number: number;
  title: string;
  state: string;
  user: { login: string };
  created_at: string;
  labels: Array<{ name: string }>;
  html_url: string;
}

interface GitHubPR {
  number: number;
  title: string;
  state: string;
  user: { login: string };
  created_at: string;
  draft: boolean;
  mergeable_state?: string;
  html_url: string;
}

export type GitHubAction =
  | "list_repos"
  | "list_issues"
  | "create_issue"
  | "list_prs"
  | "view_pr"
  | "search"
  | "search_issues"
  | "close_issue"
  | "create_label";

export interface GitHubParams {
  action: GitHubAction;
  repo?: string;        // owner/repo format
  title?: string;       // for create_issue
  body?: string;        // for create_issue
  state?: string;       // open/closed/all (default: open)
  pr_number?: number;   // for view_pr
  query?: string;       // for search, search_issues
  labels?: string[];    // for create_issue (optional label names)
  comment?: string;     // for close_issue
  name?: string;        // for create_label
  color?: string;       // for create_label (hex without #)
  description?: string; // for create_label
  issue_number?: number; // for close_issue
}

export interface GitHubResult {
  action: GitHubAction;
  data: unknown;
  summary: string;
}

const API = "https://api.github.com";

async function ghFetch(
  path: string,
  config: GitHubConfig,
  opts?: { method?: string; body?: string },
): Promise<unknown> {
  const res = await fetch(`${API}${path}`, {
    method: opts?.method ?? "GET",
    headers: {
      Authorization: `Bearer ${config.pat}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(opts?.body ? { "Content-Type": "application/json" } : {}),
    },
    body: opts?.body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${res.status}: ${text.slice(0, 200)}`);
  }

  return res.json();
}

async function listRepos(config: GitHubConfig): Promise<GitHubRepo[]> {
  const repos = (await ghFetch(
    `/user/repos?sort=updated&per_page=30&type=owner`,
    config,
  )) as GitHubRepo[];
  return repos;
}

async function listIssues(
  repo: string,
  state: string,
  config: GitHubConfig,
): Promise<GitHubIssue[]> {
  const issues = (await ghFetch(
    `/repos/${repo}/issues?state=${state}&per_page=30&sort=updated`,
    config,
  )) as GitHubIssue[];
  // GitHub API returns PRs in issues endpoint — filter them out
  return issues.filter((i) => !("pull_request" in i));
}

async function createIssue(
  repo: string,
  title: string,
  body: string,
  config: GitHubConfig,
  labels?: string[],
): Promise<GitHubIssue> {
  return (await ghFetch(`/repos/${repo}/issues`, config, {
    method: "POST",
    body: JSON.stringify({ title, body, ...(labels ? { labels } : {}) }),
  })) as GitHubIssue;
}

async function listPRs(
  repo: string,
  state: string,
  config: GitHubConfig,
): Promise<GitHubPR[]> {
  return (await ghFetch(
    `/repos/${repo}/pulls?state=${state}&per_page=30&sort=updated`,
    config,
  )) as GitHubPR[];
}

async function viewPR(
  repo: string,
  number: number,
  config: GitHubConfig,
): Promise<GitHubPR> {
  return (await ghFetch(`/repos/${repo}/pulls/${number}`, config)) as GitHubPR;
}

async function searchCode(
  query: string,
  config: GitHubConfig,
): Promise<{ total_count: number; items: Array<{ name: string; path: string; repository: { full_name: string }; html_url: string }> }> {
  return (await ghFetch(
    `/search/code?q=${encodeURIComponent(query)}&per_page=10`,
    config,
  )) as { total_count: number; items: Array<{ name: string; path: string; repository: { full_name: string }; html_url: string }> };
}

async function searchIssues(
  query: string,
  config: GitHubConfig,
): Promise<{ total_count: number; items: GitHubIssue[] }> {
  return (await ghFetch(
    `/search/issues?q=${encodeURIComponent(query)}&per_page=30`,
    config,
  )) as { total_count: number; items: GitHubIssue[] };
}

async function closeIssue(
  repo: string,
  issue_number: number,
  config: GitHubConfig,
  comment?: string,
): Promise<GitHubIssue> {
  // Add comment if provided
  if (comment) {
    await ghFetch(`/repos/${repo}/issues/${issue_number}/comments`, config, {
      method: "POST",
      body: JSON.stringify({ body: comment }),
    });
  }

  // Close the issue
  return (await ghFetch(`/repos/${repo}/issues/${issue_number}`, config, {
    method: "PATCH",
    body: JSON.stringify({ state: "closed" }),
  })) as GitHubIssue;
}

async function ensureLabel(
  repo: string,
  name: string,
  config: GitHubConfig,
  color?: string,
  description?: string,
): Promise<{ name: string; color: string; created: boolean }> {
  // Default colors for known labels
  const defaultColors: Record<string, string> = {
    "lobsec-qa": "0e8a16",       // green
    "js-error": "d73a4a",         // red
    "network-error": "f9d0c4",    // salmon
    "visual-regression": "5319e7", // purple
  };

  const finalColor = color ?? defaultColors[name] ?? "ededed"; // gray default
  const finalDescription = description ?? "";

  try {
    // Check if label exists
    await ghFetch(`/repos/${repo}/labels/${encodeURIComponent(name)}`, config);
    // Label exists, return silently
    return { name, color: finalColor, created: false };
  } catch (err) {
    // Label doesn't exist (404), create it
    const label = (await ghFetch(`/repos/${repo}/labels`, config, {
      method: "POST",
      body: JSON.stringify({ name, color: finalColor, description: finalDescription }),
    })) as { name: string; color: string };
    return { ...label, created: true };
  }
}

// ── Formatters (for githubAction return values) ──

function formatSearchIssues(results: { total_count: number; items: GitHubIssue[] }): string {
  if (results.total_count === 0) return "No issues found.";
  const lines = results.items.map((i) => {
    const labels = i.labels.length > 0 ? ` [${i.labels.map((l) => l.name).join(", ")}]` : "";
    return `#${i.number} ${i.title} (${i.state})${labels} — ${i.html_url}`;
  });
  return `Issues (${results.total_count} total, showing ${results.items.length}):\n${lines.join("\n")}`;
}

function formatCloseIssue(issue: GitHubIssue, comment?: string): string {
  const commentNote = comment ? " with comment" : "";
  return `Closed issue #${issue.number}${commentNote}: ${issue.title}\n${issue.html_url}`;
}

function formatCreateLabel(label: { name: string; color: string; created: boolean }): string {
  if (label.created) {
    return `Created label "${label.name}" (color: #${label.color})`;
  }
  return `Label "${label.name}" already exists`;
}

export async function githubAction(
  params: GitHubParams,
  config: GitHubConfig,
): Promise<GitHubResult> {
  const { action, repo, state = "open" } = params;

  switch (action) {
    case "list_repos": {
      const repos = await listRepos(config);
      return {
        action,
        data: repos,
        summary: formatRepos(repos),
      };
    }
    case "list_issues": {
      if (!repo) throw new Error("repo is required for list_issues");
      const issues = await listIssues(repo, state, config);
      return {
        action,
        data: issues,
        summary: formatIssues(issues, repo),
      };
    }
    case "create_issue": {
      if (!repo) throw new Error("repo is required for create_issue");
      if (!params.title) throw new Error("title is required for create_issue");
      const issue = await createIssue(repo, params.title, params.body ?? "", config, params.labels);
      return {
        action,
        data: issue,
        summary: `Created issue #${issue.number}: ${issue.title}\n${issue.html_url}`,
      };
    }
    case "list_prs": {
      if (!repo) throw new Error("repo is required for list_prs");
      const prs = await listPRs(repo, state, config);
      return {
        action,
        data: prs,
        summary: formatPRs(prs, repo),
      };
    }
    case "view_pr": {
      if (!repo) throw new Error("repo is required for view_pr");
      if (!params.pr_number) throw new Error("pr_number is required for view_pr");
      const pr = await viewPR(repo, params.pr_number, config);
      return {
        action,
        data: pr,
        summary: formatPRDetail(pr),
      };
    }
    case "search": {
      if (!params.query) throw new Error("query is required for search");
      const results = await searchCode(params.query, config);
      return {
        action,
        data: results,
        summary: formatSearch(results),
      };
    }
    case "search_issues": {
      if (!params.query) throw new Error("query is required for search_issues");
      const results = await searchIssues(params.query, config);
      return {
        action,
        data: results,
        summary: formatSearchIssues(results),
      };
    }
    case "close_issue": {
      if (!repo) throw new Error("repo is required for close_issue");
      if (!params.issue_number) throw new Error("issue_number is required for close_issue");
      const issue = await closeIssue(repo, params.issue_number, config, params.comment);
      return {
        action,
        data: issue,
        summary: formatCloseIssue(issue, params.comment),
      };
    }
    case "create_label": {
      if (!repo) throw new Error("repo is required for create_label");
      if (!params.name) throw new Error("name is required for create_label");
      const label = await ensureLabel(repo, params.name, config, params.color, params.description);
      return {
        action,
        data: label,
        summary: formatCreateLabel(label),
      };
    }
    default:
      throw new Error(`Unknown action: ${action}. Use: list_repos, list_issues, create_issue, list_prs, view_pr, search, search_issues, close_issue, create_label`);
  }
}

// ── Formatters ──────────────────────────────────────────────────────────────

function formatRepos(repos: GitHubRepo[]): string {
  if (repos.length === 0) return "No repositories found.";
  const lines = repos.map((r) => {
    const vis = r.private ? "[private]" : "[public]";
    const lang = r.language ? ` (${r.language})` : "";
    const stars = r.stargazers_count > 0 ? ` ★${r.stargazers_count}` : "";
    const desc = r.description ? ` — ${r.description}` : "";
    return `${vis} ${r.full_name}${lang}${stars}${desc}`;
  });
  return `Repositories (${repos.length}):\n${lines.join("\n")}`;
}

function formatIssues(issues: GitHubIssue[], repo: string): string {
  if (issues.length === 0) return `No issues found in ${repo}.`;
  const lines = issues.map((i) => {
    const labels = i.labels.length > 0 ? ` [${i.labels.map((l) => l.name).join(", ")}]` : "";
    return `#${i.number} ${i.title} (${i.state})${labels} — by ${i.user.login}`;
  });
  return `Issues in ${repo} (${issues.length}):\n${lines.join("\n")}`;
}

function formatPRs(prs: GitHubPR[], repo: string): string {
  if (prs.length === 0) return `No pull requests found in ${repo}.`;
  const lines = prs.map((pr) => {
    const draft = pr.draft ? " [draft]" : "";
    return `#${pr.number} ${pr.title} (${pr.state})${draft} — by ${pr.user.login}`;
  });
  return `Pull requests in ${repo} (${prs.length}):\n${lines.join("\n")}`;
}

function formatPRDetail(pr: GitHubPR): string {
  return [
    `PR #${pr.number}: ${pr.title}`,
    `State: ${pr.state}${pr.draft ? " (draft)" : ""}`,
    `Author: ${pr.user.login}`,
    `Created: ${pr.created_at}`,
    `URL: ${pr.html_url}`,
  ].join("\n");
}

function formatSearch(results: { total_count: number; items: Array<{ name: string; path: string; repository: { full_name: string }; html_url: string }> }): string {
  if (results.total_count === 0) return "No results found.";
  const lines = results.items.map(
    (i) => `${i.repository.full_name}: ${i.path}`,
  );
  return `Search results (${results.total_count} total, showing ${results.items.length}):\n${lines.join("\n")}`;
}

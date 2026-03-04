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
  | "search";

export interface GitHubParams {
  action: GitHubAction;
  repo?: string;        // owner/repo format
  title?: string;       // for create_issue
  body?: string;        // for create_issue
  state?: string;       // open/closed/all (default: open)
  pr_number?: number;   // for view_pr
  query?: string;       // for search
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
): Promise<GitHubIssue> {
  return (await ghFetch(`/repos/${repo}/issues`, config, {
    method: "POST",
    body: JSON.stringify({ title, body }),
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
      const issue = await createIssue(repo, params.title, params.body ?? "", config);
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
    default:
      throw new Error(`Unknown action: ${action}. Use: list_repos, list_issues, create_issue, list_prs, view_pr, search`);
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

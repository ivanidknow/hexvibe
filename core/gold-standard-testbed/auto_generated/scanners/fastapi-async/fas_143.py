# Vulnerable: FAS-143
requests.post(param, data={"hello", "world"})
@app.route("/ok")
def ok():
    requests.get("https://www.google.com")
# Non-flask false positive check from https://github.com/returntocorp/semgrep-rules/issues/3053
class GitlabApi(ScmApiBase):
    @cachedmethod("cache")
    @handle_errors
    @tracer_wrap
    def get_file(self, repo_name: str, commit_sha: str, file_path: str) -> str:
...
        )
        params = {"ref": commit_sha, "file_path": file_path}

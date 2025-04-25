import subprocess
from pathlib import Path

def run(cmd):
    print(f"▶ {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def write_file(path, content):
    Path(path).write_text(content)
    print(f"✅ {path} 생성됨.")

def main():
    # 1. semantic-release 설치
    run("uv pip install python-semantic-release build")

    # 2. .releaserc.toml 설정
    write_file(".releaserc.toml", """\
[semantic_release]
version_variable = ["src/my_package/__init__.py:__version__"]
build_command = "uv pip install build && python -m build"
upload_to_pypi = true
upload_to_release = true
changelog_file = "CHANGELOG.md"
commit_parser = "conventional"
tag_format = "v{version}"
""")

    # 3. GitHub Actions 릴리즈 워크플로우
    Path(".github/workflows").mkdir(parents=True, exist_ok=True)
    write_file(".github/workflows/release.yml", """\
name: Release

on:
  push:
    branches: [master]

permissions:
  contents: write
  id-token: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install uv and semantic-release
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          uv pip install python-semantic-release build

      - name: Run Semantic Release
        run: semantic-release publish
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PYPI_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
""")

    print("\n🎉 Semantic-release 설정 완료!")
    print("💡 커밋은 `cz commit` 으로 작성해야 릴리즈 조건 충족됨.")

if __name__ == "__main__":
    main()
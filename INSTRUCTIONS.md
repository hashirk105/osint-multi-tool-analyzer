# Complete instructions: run it and upload it to GitHub

## A. Run the program
1. Install Python 3.9+ from https://python.org (Windows: tick "Add Python to PATH").
   Linux only: `sudo apt install python3-tk`.
2. Open a terminal in the project folder, then:
   ```
   python -m venv .venv
   .venv\Scripts\activate          (Windows)   |   source .venv/bin/activate   (macOS/Linux)
   pip install -r requirements.txt
   python app.py
   ```
3. Get free API keys (links are also in the app's "API Keys" tab):
   VirusTotal, Shodan, AbuseIPDB, IPinfo, GreyNoise.
4. Paste the keys in the "API Keys" tab (or copy `.env.example` to `.env` and fill it in).
5. Type a domain (e.g. `example.com`) -> click Analyze -> view "Comparison Table" -> click "Export to Excel (.xlsx)".
6. Optional offline self-test (no keys needed): `python -m unittest discover -s tests -v`

## B. Upload to GitHub
1. Create an account at https://github.com, click New repository, name it `osint-multi-tool-analyzer`,
   set it Public, do NOT tick "Add README", click Create.
2. Install Git (https://git-scm.com), then in the project folder:
   ```
   git init
   git add .
   git commit -m "OSINT multi-tool website analyzer"
   git branch -M main
   git remote add origin https://github.com/<YOUR-USERNAME>/osint-multi-tool-analyzer.git
   git push -u origin main
   ```
   (GitHub asks you to sign in; if it asks for a password use a Personal Access Token:
   Settings > Developer settings > Tokens.)
3. Check `.env` is NOT in the repo (it is git-ignored). Never upload API keys.
4. Submit the repository link: https://github.com/<YOUR-USERNAME>/osint-multi-tool-analyzer

No Git? On the repo page click "Add file > Upload files", drag in the unzipped files (including the
`tests` folder), and click Commit.

## C. Suggested extras for submission
Run the tool on a domain you are allowed to test, export the .xlsx, and add a screenshot of the GUI
and the Excel file to the repo (e.g. `screenshots/`).

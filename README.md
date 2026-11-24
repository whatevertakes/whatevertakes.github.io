# WhateverTakes — official research site

Official website and research blog of WhateverTakes (WT).

## Local development

Use Node.js compatible with the engines field in package.json.

```sh
npm ci
npm run dev
npm run build
npm run preview
```

## Publishing

Use a branch and pull request. Add reviewed posts to src/pages/blog/ as Markdown, link them in the blog index, and verify the build. Record authors, evidence and limitations. Do not publish credentials, private infrastructure details or embargoed findings.

Member links are maintained in src/data/members.ts. Only add confirmed public websites.

GitHub Pages: select GitHub Actions in repository Settings → Pages, then run the deployment workflow. The deployment URL is https://whatevertakes.github.io/.

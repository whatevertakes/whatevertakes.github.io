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

Use a branch and pull request. Add reviewed Markdown posts to src/pages/blog/ (English) or src/pages/ko/blog/ (Korean); each index lists its own posts automatically. Add reciprocal translation frontmatter URLs when both versions exist, then verify the build. Record authors, evidence and limitations. Do not publish credentials, private infrastructure details or embargoed findings.

Member links are maintained in src/data/members.ts. Only add confirmed public websites.

GitHub Pages: select GitHub Actions in repository Settings → Pages, then run the deployment workflow. The deployment URL is https://whatevertakes.github.io/.

## Languages

English uses the root routes; Korean uses /ko/. The shared layout provides a language switch on every page. Both languages share the same member data and styles. For untranslated articles, the switch opens the other language's blog index.

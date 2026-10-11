# 99MS

Live salary clock, counted to the millisecond, with shifts, savings, investments and projects.

**Production: https://99ms.dk.** This repo is the only source of the app. Every push to `main` deploys.

- Single-page app with no build step: everything is in `index.html`.
- `icon.svg`, `apple-touch-icon.png`, `icon-192.png`, `icon-512.png` and `manifest.webmanifest` give it a home-screen icon.
- Account sync and email-link login use Supabase (see `SYNC` in `index.html`). In Supabase → Authentication → URL Configuration, the Site URL is `https://99ms.dk` and `https://99ms.dk/**` is an allowed redirect URL.
- Hosting: GitHub Pages from the `main` branch, root folder. `CNAME` sets the custom domain.

The old address, `rodriguez594.github.io/99management/salary/`, only forwards here. It passes along any data saved in that browser (in the URL hash), and 99ms.dk asks before adding it.

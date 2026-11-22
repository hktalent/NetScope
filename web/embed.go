package web

import "embed"

//go:embed index.html app.js style.css footer.js
var FS embed.FS

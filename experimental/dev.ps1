clojure -M `
	--main cljs.main `
	--compile-opts compile.edn `
	--repl-opts repl.edn `
	--verbose `
	--watch src `
	--compile libwtf.experimental `
	--repl `
	--serve 127.0.0.1:8080
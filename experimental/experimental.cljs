(ns libwtf.experimental
  (:require
   [cljs.core.async :refer [go]]
   [cljs.core.async.interop :refer-macros [<p!]]))

(comment

(def url "https://localhost:8443/echo")

(def wt (new js/WebTransport url))

(go
  (let []
    (try
      (<p! (.-ready wt))
      (catch js/Error err (js/console.log (ex-cause err))))))

(go
  (let [enc (new js/TextEncoder "utf-8")
        data (.encode enc "hello world")
        w (some-> wt .-datagrams .-writable .getWriter)]
    (try
      (<p! (.write w data))
      (catch js/Error err (js/console.log (ex-cause err))))))

(go
  (let [d (new js/TextDecoder "utf-8")
        r (some-> wt .-datagrams .-readable .getReader)]
    (try
      (loop []
        (let [{value "value" done "done"} (js->clj (<p! (.read r)))]
          (js/alert (.decode d value))
          (when-not done (recur))))
      (catch js/Error err (js/console.log (ex-cause err))))))

(defn log-stream-data [readable]
  (go
    (let [d (new js/TextDecoderStream "utf-8")
          r (-> readable (.pipeThrough d) .getReader)]
      (try
        (loop []
          (let [{value "value" done "done"} (js->clj (<p! (.read r)))]
            (js/console.log value)
            (when-not done (recur))))
        (catch js/Error err (js/console.log (ex-cause err)))))))

(go
  (let [enc (new js/TextEncoder "utf-8")
        data (.encode enc "hello world")
        s (<p! (.createBidirectionalStream wt))
        w (some-> s .-writable .getWriter)]
    (try
      (log-stream-data (.-readable s))
      (<p! (.write w data))
      (<p! (.close w))
      (catch js/Error err (js/console.log (ex-cause err))))))

)

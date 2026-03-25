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
          (js/console.log (.decode d value))
          (when-not done (recur))))
      (catch js/Error err (js/console.log (ex-cause err))))))

(defn log-stream-data [readable]
  (go
    (let [d (new js/TextDecoderStream "utf-8")
          r (-> readable (.pipeThrough d) .getReader)]
      (try
        ;(<p! (.-ready readable))
        (loop []
          (let [{value "value" done "done"} (js->clj (<p! (.read r)))]
            (if (nil? value)
              (js/console.log "nil value in stream reader")
              (js/console.log value))
            (when-not done (recur))))
        (catch js/Error err (js/console.log (ex-cause err)))))))

(def enc (new js/TextEncoder "utf-8"))
(def data (.encode enc "hello world"))

;; wait
(go (def s (<p! (.createBidirectionalStream wt))))

;; wait
(log-stream-data (.-readable s))
(def w (some-> s .-writable .getWriter))

(go (println (<p! (.write w data))))

(.write w data)

(.close w)

)

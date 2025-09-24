
```mermaid
graph TD;
        __start__([<p>__start__</p>]):::first
        analyze(analyze)
        write(write)
        commit(commit)
        __end__([<p>__end__</p>]):::last
        __start__ --> analyze;
        analyze --> write;
        write --> commit;
        commit --> __end__;
        classDef default fill:#f2f0ff,line-height:1.2
        classDef first fill-opacity:0
        classDef last fill:#bfb6fc
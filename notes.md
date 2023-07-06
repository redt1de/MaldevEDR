TODO:
    - seperate config from etw so we can use yaml for all modules.
    - implement a module tag for console output. need to give each module its own console logger.
    - de-dupe etw events, some come in twice, especially hooked funcs
    - fix logger setoutput and enable debug. we changed logger so now some will miss.
    - verbose flags are screwy in analyze

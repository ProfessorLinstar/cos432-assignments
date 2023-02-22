call setreg('q', ':bufdo if &filetype==''java'' | 1,10s#^\(// \)\?\(\(package\|import\) com.princeton\)\@=#\={''// '':'''','''':''// ''}[submatch(1)]#e | noh | update | endif', 'c')

def remove_comments_from_mib(mib):
    CAPTURE, COMMENT, MLCOMMENT, DQUOTE, SQUOTE = range(5)

    context = CAPTURE
    prev = None
    out = []
    p = 0

    for i, c in enumerate(mib):
        if context == CAPTURE:
            if c == '-' and prev == '-':
                context = COMMENT
                out.append(mib[p:i - 1])
                prev = None
                continue
            if c == '*' and prev == '/':
                context = MLCOMMENT
                out.append(mib[p:i - 1])
                prev = None
                continue

            if c == '"' and prev != '\\':
                context = DQUOTE
            elif c == "'" and prev != '\\':
                context = SQUOTE

        elif context == DQUOTE:
            if c == '"' and prev != '\\':
                context = CAPTURE

        elif context == SQUOTE:
            if c == "'" and prev != '\\':
                context = CAPTURE

        elif context == COMMENT:
            if c == '-' and prev == '-':
                context = CAPTURE
                p = i + 1
            elif c == '\n':
                context = CAPTURE
                p = i

        elif context == MLCOMMENT:
            if c == '/' and prev == '*':
                context = CAPTURE
                p = i + 1

        prev = c

    out.append(mib[p:i + 1])

    return ''.join(filter(lambda x: x.strip(), out))

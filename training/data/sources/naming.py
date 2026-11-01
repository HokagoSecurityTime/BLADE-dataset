"""Resource naming shared by extraction and metadata-only reanalysis."""
VERBS = {'get', 'retrieve', 'list', 'search', 'create', 'update', 'delete', 'fetch', 'find'}


def resource_name(path: str) -> str:
    segments = [part for part in path.split('/') if part and not part.startswith('{')]
    while segments and segments[-1].casefold() in VERBS:
        segments.pop()
    return (segments[-1] if segments else 'resource').replace('-', '_')

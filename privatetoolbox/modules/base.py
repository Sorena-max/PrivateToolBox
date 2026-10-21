from ..actions import Finding, Plan


class Module:
    id = ""
    weight = 0

    def scan(self, ctx):
        raise NotImplementedError

    def plan(self, ctx):
        raise NotImplementedError

    def verify(self, ctx):
        """List of (ok, i18n key, params)."""
        return []

    # small helpers so modules read clearly
    def ok(self, key, **params):
        return Finding(self.id, "ok", key, params, self.weight)

    def todo(self, key, **params):
        return Finding(self.id, "todo", key, params, self.weight)

    def info(self, key, **params):
        return Finding(self.id, "info", key, params, 0)

    def na(self, key, **params):
        return Finding(self.id, "na", key, params, 0)

    def skip(self, key, **params):
        return Plan(self.id, skip=(key, params))

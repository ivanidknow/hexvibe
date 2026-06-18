# Vulnerable: FAS-103
def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
class ModelIssue1106(models.Model):

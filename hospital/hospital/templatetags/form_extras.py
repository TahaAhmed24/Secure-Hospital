from django import template
register = template.Library()

@register.filter
def is_checkbox(field):
    return field.field.widget.__class__.__name__ in ["CheckboxInput", "CheckboxSelectMultiple"]



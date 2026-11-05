# Readable tab-completion menu: prompt_toolkit's default highlights the current
# entry as white on mid-grey. IPython's highlighting_style_overrides only takes
# pygments tokens, so merge a prompt_toolkit style on top of IPython's instead.
from prompt_toolkit.styles import Style, merge_styles

_menu = Style.from_dict({
    "completion-menu.completion": "bg:#e4e4e4 #000000",
    "completion-menu.completion.current": "noreverse bg:#005f87 #ffffff bold",
    "completion-menu.meta.completion": "bg:#d0d0d0 #000000",
    "completion-menu.meta.completion.current": "noreverse bg:#005f87 #ffffff",
})

_ip = get_ipython()
if getattr(_ip, "pt_app", None) is not None:
    _ip.pt_app.style = merge_styles([_ip.pt_app.style, _menu])   # still follows %colors

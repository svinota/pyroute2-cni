# Configuration file for the Sphinx documentation builder.
#

def get_version():
    with open('../VERSION', 'r') as f:
        return f.read().strip()

project = 'pyroute2-cni'
copyright = '2025, Peter Saveliev'
author = 'Peter Saveliev'
release = get_version()

extensions = ['aafigure.sphinxext']

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


html_theme = 'default'
html_static_path = ['_static']
html_js_files = ['fixup.js']
html_css_files = ['custom.css']
html_static_path = ['_static']

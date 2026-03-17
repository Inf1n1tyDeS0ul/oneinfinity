import ast
import os
import json

def analyze_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content)
        classes = []
        functions = []
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                methods = []
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) or isinstance(item, ast.AsyncFunctionDef):
                        methods.append(item.name)
                classes.append({
                    'name': node.name,
                    'doc': ast.get_docstring(node),
                    'methods': methods
                })
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                functions.append({
                    'name': node.name,
                    'doc': ast.get_docstring(node)
                })
        return {'classes': classes, 'functions': functions}
    except Exception as e:
        return {'error': str(e)}

def main():
    result = {}
    for root, dirs, files in os.walk('.'):
        if 'venv' in root or '.git' in root or 'node_modules' in root or '__pycache__' in root or 'pip' in root or 'path' in root:
            continue
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                res = analyze_file(path)
                if not 'error' in res and (res['classes'] or res['functions']):
                    result[path] = res
    with open('analysis_result.json', 'w') as f:
        json.dump(result, f, indent=2)

if __name__ == '__main__':
    main()

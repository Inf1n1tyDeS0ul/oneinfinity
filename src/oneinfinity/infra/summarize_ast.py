import json

with open('analysis_result.json', 'r') as f:
    data = json.load(f)

for path, info in data.items():
    classes = info.get('classes', [])
    functions = info.get('functions', [])
    
    if classes or functions:
        print(f"=== {path} ===")
        for cls in classes:
            doc = (cls.get('doc') or '')[:100].replace('\n', ' ')
            print(f"  Class: {cls['name']} - Methods: {', '.join(cls.get('methods', []))}")
        for func in functions:
            print(f"  Func: {func['name']}")


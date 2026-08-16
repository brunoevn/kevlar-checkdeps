with open('kevlar.py', 'r') as f:
    content = f.read()

replacement2 = """        # Optimization: Use O(1) set membership lookups
        up_to_date = sum(
            1 for r in results if r["status"] in {"up-to-date", "local"}
        )"""
content = content.replace('''        up_to_date = sum(
            1 for r in results if r["status"] in {"up-to-date", "local"}
        )''', replacement2, 1)

with open('kevlar.py', 'w') as f:
    f.write(content)

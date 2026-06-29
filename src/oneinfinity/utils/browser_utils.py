def get_accessibility_script():
    return """
    (function() {
        function getElementPath(el) {
            if (el.id) return '#' + el.id;
            if (el.name) return `[name="${el.name}"]`;
            return el.tagName.toLowerCase();
        }

        const interactiveElements = Array.from(document.querySelectorAll('a, button, input, select, textarea, [role="button"], [onclick]'));
        
        return interactiveElements.map(el => {
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return null;
            
            return {
                tag: el.tagName.toLowerCase(),
                text: (el.innerText || el.value || el.placeholder || el.getAttribute('aria-label') || '').trim().substring(0, 50),
                path: getElementPath(el),
                type: el.type || null,
                is_visible: true
            };
        }).filter(x => x !== null);
    })();
    """

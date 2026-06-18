// Vulnerable: JAVA-137
this._elt.innerHTML = '<svg viewBox="-20 -20 140 140" width="100" height="100">' +
            '<defs>' +
            '<marker id="prism-previewer-easing-marker" viewBox="0 0 4 4" refX="2" refY="2" markerUnits="strokeWidth">' +
            '<circle cx="2" cy="2" r="1.5" />' +
            '</marker>' +
            '</defs>' +
            '<path d="M0,100 C20,50, 40,30, 100,0" />' +
            '<line x1="0" y1="100" x2="20" y2="50" marker-start="url(' + location.href + '#prism-previewer-easing-marker)" marker-end="url(' + location.href + '#prism-previewer-easing-marker)" />' +
            '<line x1="100" y1="0" x2="40" y2="30" marker-start="url(' + location.href + '#prism-previewer-easing-marker)" marker-end="url(' + location.href + '#prism-previewer-easing-marker)" />' +
            '</svg>';
...
    value = queries[key];
    if (angular.isDefined(value)) {

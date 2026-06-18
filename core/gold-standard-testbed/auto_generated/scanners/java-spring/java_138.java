// Vulnerable: JAVA-138
this.$element = jQuery(["<span class=\"jqtree-title jqtree-dragging\">",nodeName, "</span>"].join());
        this.$element.css("position", "absolute");
        $tree.append(this.$element);
    }
    DragElement.prototype.move = function (pageX, pageY) {
        this.$element.offset({
            left: pageX - this.offsetX,
            top: pageY - this.offsetY
        });
    };
...
    value = queries[key];
    if (angular.isDefined(value)) {

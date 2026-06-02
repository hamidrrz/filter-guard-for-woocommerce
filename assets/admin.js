(function () {
    'use strict';

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    ready(function () {
        var root = document.querySelector('.filter-guard-for-woocommerce-wrap');
        if (!root) {
            return;
        }

        root.classList.add('filter-guard-for-woocommerce-js-ready');

        var helpButtons = root.querySelectorAll('.filter-guard-for-woocommerce-help-button');
        helpButtons.forEach(function (button) {
            button.addEventListener('click', function (event) {
                event.stopPropagation();
            });
            button.addEventListener('keydown', function (event) {
                if (event.key === 'Escape') {
                    button.blur();
                }
            });
        });

        var form = root.querySelector('.filter-guard-for-woocommerce-settings-form');
        if (!form) {
            return;
        }

        var headings = Array.prototype.slice.call(form.querySelectorAll(':scope > h2.filter-guard-for-woocommerce-section-heading'));
        if (!headings.length) {
            return;
        }

        var i18n = window.FilterGuardForWooCommerceAdmin || {};
        var controls = document.createElement('div');
        controls.className = 'filter-guard-for-woocommerce-accordion-controls';
        var expandButton = document.createElement('button');
        expandButton.type = 'button';
        expandButton.className = 'button';
        expandButton.textContent = i18n.expandAll || 'Expand all settings';
        var collapseButton = document.createElement('button');
        collapseButton.type = 'button';
        collapseButton.className = 'button';
        collapseButton.textContent = i18n.collapseAdvanced || 'Collapse advanced settings';
        controls.appendChild(expandButton);
        controls.appendChild(collapseButton);
        form.insertBefore(controls, headings[0]);

        var detailsList = [];

        headings.forEach(function (heading, index) {
            var details = document.createElement('details');
            details.className = 'filter-guard-for-woocommerce-accordion';
            if (index === 0) {
                details.open = true;
            }

            var summary = document.createElement('summary');
            summary.className = 'filter-guard-for-woocommerce-accordion-summary';

            while (heading.firstChild) {
                summary.appendChild(heading.firstChild);
            }

            var body = document.createElement('div');
            body.className = 'filter-guard-for-woocommerce-accordion-body';

            heading.parentNode.replaceChild(details, heading);
            details.appendChild(summary);

            var node = details.nextSibling;
            while (node && !(node.nodeType === 1 && (node.matches('h2.filter-guard-for-woocommerce-section-heading') || node.matches('.filter-guard-for-woocommerce-settings-actions')))) {
                var next = node.nextSibling;
                body.appendChild(node);
                node = next;
            }

            details.appendChild(body);
            detailsList.push(details);
        });

        var buttons = controls.querySelectorAll('button');
        if (buttons[0]) {
            buttons[0].addEventListener('click', function () {
                detailsList.forEach(function (details) {
                    details.open = true;
                });
            });
        }
        if (buttons[1]) {
            buttons[1].addEventListener('click', function () {
                detailsList.forEach(function (details, index) {
                    details.open = index === 0;
                });
            });
        }
    });
}());

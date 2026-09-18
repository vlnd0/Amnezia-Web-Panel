/**
 * Searchable select — progressive enhancement for long <select> lists.
 *
 * Any `<select data-searchable>` is wrapped in a filterable dropdown: a
 * trigger button styled like .form-select, a search box and a filtered
 * option list with keyboard navigation.
 *
 * The original <select> stays in the DOM (visually hidden) and remains the
 * single source of truth, so existing code that reads `.value`, sets it, or
 * listens for `change` keeps working untouched.
 *
 * Labels come from data attributes so translations stay in the templates:
 *   data-search-placeholder="..."   search box placeholder
 *   data-search-empty="..."         shown when nothing matches
 */
(function () {
    'use strict';

    var ID_SEQ = 0;

    function textOf(option) {
        return (option.textContent || '').trim();
    }

    function SearchableSelect(select) {
        this.select = select;
        this.id = 'ss-' + (++ID_SEQ);
        this.open = false;
        this.activeIndex = -1;
        this.items = [];
        this.build();
    }

    SearchableSelect.prototype.build = function () {
        var self = this;
        var select = this.select;

        var wrapper = document.createElement('div');
        wrapper.className = 'searchable-select';

        var trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'form-select searchable-select-trigger';
        trigger.setAttribute('aria-haspopup', 'listbox');
        // Option text is user data (names, emails) and may run counter to the
        // page direction; let the browser pick per string instead of forcing
        // the UI direction onto it.
        trigger.setAttribute('dir', 'auto');
        trigger.setAttribute('aria-expanded', 'false');
        if (select.id) {
            trigger.setAttribute('aria-labelledby', select.id + '-label');
        }

        var panel = document.createElement('div');
        panel.className = 'searchable-select-panel';
        panel.hidden = true;

        var searchWrap = document.createElement('div');
        searchWrap.className = 'searchable-select-search';

        var search = document.createElement('input');
        search.type = 'text';
        search.className = 'form-input';
        search.autocomplete = 'off';
        search.spellcheck = false;
        search.setAttribute('dir', 'auto');
        search.placeholder = select.dataset.searchPlaceholder || 'Search...';
        search.setAttribute('aria-controls', this.id + '-list');
        searchWrap.appendChild(search);

        var list = document.createElement('div');
        list.className = 'searchable-select-list';
        list.id = this.id + '-list';
        list.setAttribute('role', 'listbox');

        var empty = document.createElement('div');
        empty.className = 'searchable-select-empty';
        empty.textContent = select.dataset.searchEmpty || 'No matches';
        empty.hidden = true;

        panel.appendChild(searchWrap);
        panel.appendChild(list);
        panel.appendChild(empty);

        select.parentNode.insertBefore(wrapper, select);
        wrapper.appendChild(select);
        wrapper.appendChild(trigger);
        wrapper.appendChild(panel);
        select.classList.add('searchable-select-native');
        select.setAttribute('tabindex', '-1');
        select.setAttribute('aria-hidden', 'true');

        this.wrapper = wrapper;
        this.trigger = trigger;
        this.panel = panel;
        this.search = search;
        this.list = list;
        this.empty = empty;

        this.renderOptions();
        this.syncTrigger();

        trigger.addEventListener('click', function () {
            self.toggle();
        });
        trigger.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                self.show();
            }
        });
        search.addEventListener('input', function () {
            self.filter(search.value);
        });
        search.addEventListener('keydown', function (e) {
            self.onSearchKey(e);
        });
        select.addEventListener('change', function () {
            self.syncTrigger();
        });
        document.addEventListener('click', function (e) {
            if (self.open && !wrapper.contains(e.target)) {
                self.hide();
            }
        });
    };

    /** Rebuild the option list from the native <select>. */
    SearchableSelect.prototype.renderOptions = function () {
        var self = this;
        this.list.textContent = '';
        this.items = [];

        Array.prototype.forEach.call(this.select.options, function (option, index) {
            var item = document.createElement('div');
            item.className = 'searchable-select-option';
            item.setAttribute('role', 'option');
            item.setAttribute('dir', 'auto');
            item.id = self.id + '-opt-' + index;
            item.textContent = textOf(option);   // textContent: never trust option text as HTML
            item.dataset.index = String(index);
            if (option.disabled) {
                item.classList.add('is-disabled');
            }
            item.addEventListener('click', function () {
                if (option.disabled) return;
                self.choose(index);
            });
            self.list.appendChild(item);
            self.items.push({ el: item, text: textOf(option).toLowerCase(), index: index });
        });
    };

    SearchableSelect.prototype.syncTrigger = function () {
        var option = this.select.options[this.select.selectedIndex];
        this.trigger.textContent = option ? textOf(option) : '';
        var self = this;
        this.items.forEach(function (item) {
            item.el.setAttribute('aria-selected', item.index === self.select.selectedIndex ? 'true' : 'false');
        });
    };

    SearchableSelect.prototype.filter = function (query) {
        var needle = (query || '').trim().toLowerCase();
        var visible = 0;
        this.items.forEach(function (item) {
            var match = !needle || item.text.indexOf(needle) !== -1;
            item.el.hidden = !match;
            if (match) visible++;
        });
        this.empty.hidden = visible !== 0;
        this.setActive(this.firstVisibleIndex());
    };

    SearchableSelect.prototype.visibleItems = function () {
        return this.items.filter(function (item) {
            return !item.el.hidden && !item.el.classList.contains('is-disabled');
        });
    };

    SearchableSelect.prototype.firstVisibleIndex = function () {
        var visible = this.visibleItems();
        return visible.length ? visible[0].index : -1;
    };

    SearchableSelect.prototype.setActive = function (index) {
        var self = this;
        this.activeIndex = index;
        this.items.forEach(function (item) {
            var active = item.index === index;
            item.el.classList.toggle('is-active', active);
            if (active) {
                self.list.setAttribute('aria-activedescendant', item.el.id);
                var top = item.el.offsetTop;
                var bottom = top + item.el.offsetHeight;
                if (top < self.list.scrollTop) {
                    self.list.scrollTop = top;
                } else if (bottom > self.list.scrollTop + self.list.clientHeight) {
                    self.list.scrollTop = bottom - self.list.clientHeight;
                }
            }
        });
        if (index === -1) {
            this.list.removeAttribute('aria-activedescendant');
        }
    };

    SearchableSelect.prototype.moveActive = function (step) {
        var visible = this.visibleItems();
        if (!visible.length) return;
        var current = -1;
        for (var i = 0; i < visible.length; i++) {
            if (visible[i].index === this.activeIndex) { current = i; break; }
        }
        var next = current + step;
        if (next < 0) next = visible.length - 1;
        if (next >= visible.length) next = 0;
        this.setActive(visible[next].index);
    };

    SearchableSelect.prototype.onSearchKey = function (e) {
        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                this.moveActive(1);
                break;
            case 'ArrowUp':
                e.preventDefault();
                this.moveActive(-1);
                break;
            case 'Enter':
                e.preventDefault();
                if (this.activeIndex !== -1) this.choose(this.activeIndex);
                break;
            case 'Escape':
                e.preventDefault();
                this.hide();
                this.trigger.focus();
                break;
            case 'Tab':
                this.hide();
                break;
        }
    };

    SearchableSelect.prototype.choose = function (index) {
        this.select.selectedIndex = index;
        this.select.dispatchEvent(new Event('input', { bubbles: true }));
        this.select.dispatchEvent(new Event('change', { bubbles: true }));
        this.syncTrigger();
        this.hide();
        this.trigger.focus();
    };

    SearchableSelect.prototype.show = function () {
        if (this.open) return;
        this.open = true;
        this.panel.hidden = false;
        this.wrapper.classList.add('is-open');
        this.trigger.setAttribute('aria-expanded', 'true');
        this.syncTrigger();               // pick up programmatic value changes
        this.search.value = '';
        this.filter('');
        this.setActive(this.select.selectedIndex);
        this.search.focus();
    };

    SearchableSelect.prototype.hide = function () {
        if (!this.open) return;
        this.open = false;
        this.panel.hidden = true;
        this.wrapper.classList.remove('is-open');
        this.trigger.setAttribute('aria-expanded', 'false');
    };

    SearchableSelect.prototype.toggle = function () {
        this.open ? this.hide() : this.show();
    };

    /** Re-read options from the native select (call after changing them). */
    SearchableSelect.prototype.refresh = function () {
        this.renderOptions();
        this.syncTrigger();
        if (this.open) this.filter(this.search.value);
    };

    function enhance(select) {
        if (!select || select.searchableSelect) return null;
        select.searchableSelect = new SearchableSelect(select);
        return select.searchableSelect;
    }

    function enhanceAll(root) {
        var scope = root || document;
        Array.prototype.forEach.call(
            scope.querySelectorAll('select[data-searchable]'),
            enhance
        );
    }

    window.SearchableSelect = { enhance: enhance, enhanceAll: enhanceAll };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { enhanceAll(); });
    } else {
        enhanceAll();
    }
})();

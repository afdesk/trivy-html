document.addEventListener('mouseup', () => {
    isDragging = false;
    document.body.style.userSelect = '';
});

function insertAfter(referenceNode, newNode) {
    referenceNode.parentNode.insertBefore(newNode, referenceNode.nextSibling);
}

const severityOrder = {
    UNKNOWN: {order: 5},
    LOW: {order: 4},
    MEDIUM: {order: 3},
    HIGH: {order: 2},
    CRITICAL: {order: 1},
};

function attachLinksInteractivity() {
    document.querySelectorAll("td.links").forEach(function (linkCell) {
        const links = [].concat.apply([], linkCell.querySelectorAll("a"));
        [].sort.apply(links, function (a, b) {
            return a.href > b.href ? 1 : -1;
        });
        links.forEach(function (link, idx) {
            if (links.length > 0 && 0 === idx) {
                const toggleLink = document.createElement("a");
                toggleLink.innerText = "Toggle more links";
                toggleLink.href = "#toggleMore";
                toggleLink.setAttribute("class", "toggle-more-links");
                linkCell.appendChild(toggleLink);
            }
            linkCell.appendChild(link);
        });
    });

    document
        .querySelectorAll("a.toggle-more-links")
        .forEach(function (toggleLink) {
            toggleLink.onclick = function () {
                const expanded =
                    toggleLink.parentElement.getAttribute("data-more-links");
                toggleLink.parentElement.setAttribute(
                    "data-more-links",
                    "on" === expanded ? "off" : "on"
                );
                return false;
            };
        });
}

function attachFilterInteractivity() {
    const filterBar = document.querySelector(".filter_bar");
    const nameFilter = filterBar.querySelector(".filter_bar__filter_name");
    const filterable = document.querySelectorAll(".filterable");
    const cellClasses = [
        ".pkg-name",
        ".vuln",
        ".misc-type",
        ".misc-id",
        ".severity",
        ".pkg-version",
        ".pkg-key-name",
        ".pkg-key-version",
        ".pkg-key-src-name",
        ".pkg-key-src-version",
    ];

    function applyFilters(filterValue) {
        filterable.forEach((f) => {
            const cellValues = cellClasses
                .map((cl) => f.querySelector(cl))
                .filter((cell) => cell !== null)
                .map((cell) => cell.textContent || cell.innerText);

            const condition = cellValues.some((cellValue) =>
                cellValue.toUpperCase().includes(filterValue.toUpperCase())
            );

            f.style.display = condition ? "" : "none";
        });
    }

    nameFilter.addEventListener("keyup", (e) => {
        applyFilters(e.target.value);
    });
}

function attachSortInteractivity() {
    let colIx = -1;
    const tables = document.querySelectorAll("table");
    const sortTable = (tableIx, cellIndex, type, isSorded) => {
        const table = tables[tableIx];
        const tbody = table.querySelector('tbody[data-main="true"]');
        const thead = table.querySelector("thead");
        const inv = (val) => (isSorded ? -val : val);
        const compare = (a, b) => {
            if (!a.cells[cellIndex] || !b.cells[cellIndex]) return 0;
            const rowA = a.cells[cellIndex].innerHTML;
            const rowB = b.cells[cellIndex].innerHTML;
            if (type === "string") {
                if (rowA < rowB) return inv(-1);
                if (rowA > rowB) return inv(1);
                return 0;
            }
            if (type === "severity") {
                const orderA = severityOrder[rowA].order;
                const orderB = severityOrder[rowB].order;
                if (orderA < orderB) return inv(-1);
                if (orderA > orderB) return inv(1);
                return 0;
            }
        };
        let rows = Array(...tbody.rows);
        rows.sort(compare);
        table.removeChild(tbody);
        rows.forEach((row) => {
            tbody.appendChild(row);
        });
        insertAfter(thead, tbody);
    };
    tables.forEach((table, tableIx) => {
        table.addEventListener("click", (e) => {
            e.stopPropagation();
            const el = e.target;
            const type = el.getAttribute("data-type");
            const sortable = el.getAttribute("data-sortable") === "true";
            if (el.nodeName !== "TH" || !sortable) return;
            const cellIndex = el.cellIndex;
            sortTable(tableIx, cellIndex, type, colIx === cellIndex);
            colIx = colIx === cellIndex ? -1 : cellIndex;
        });
    });
}

document.addEventListener("DOMContentLoaded", () => {
    attachLinksInteractivity();
    attachSortInteractivity();
    attachFilterInteractivity();
});
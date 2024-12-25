const codeNode = 1 << 1;
const occurrenceNode = 1 << 2;
let inWindow = false;
let currentTable;
let cy = cytoscape({
    container: document.querySelector('.graph'),
    elements: [],
    style: [
        {
            selector: 'node',
            style: {
                label: 'data(label)',
                'background-color': '#666',
                color: '#000',
                'text-valign': 'center',
                'text-halign': 'center',
                width: '80px',
                height: '80px',
            },
        },
        {
            selector: `node[type=${codeNode}]`,
            style: {
                'background-color': '#c8c8c8',
                'font-size': '14px',
                'text-valign': 'center',
                'text-halign': 'center',
            },
        },
        {
            selector: `node[type=${occurrenceNode}]`,
            style: {'background-color': '#1E90FF'},
        },
        {
            selector: 'edge',
            style: {
                label: 'data(label)',
                width: 3,
                'line-color': '#ccc',
                'curve-style': 'bezier',
                'target-arrow-color': 'black',
                'target-arrow-shape': 'triangle',
            },
        },
    ],
    layout: {
        name: 'cose',
    },
});

async function init() {
    function createSublist(tableIndex, misconfigurations) {
        const table = document.querySelector(`.misc-table[data-index = "${tableIndex}"]`);
        const content = document.querySelector(`.content[data-index = "${tableIndex}"]`)
        const allContent = document.querySelectorAll('.content');
        const allTables = document.querySelectorAll('table');
        const info = document.getElementById('info');

        misconfigurations.forEach((misconfig, idx) => {
            const listItem = document.querySelector(`[data-index="${tableIndex} ${idx}"]`);
            listItem.addEventListener('click', function (e) {
                e.stopPropagation();
                currentTable = table;
                if (!inWindow) {
                    changeContainer(tableIndex)
                    allTables.forEach((table) => {
                        table.style.width = "100%";

                    });

                    allContent.forEach((item) => {
                        item.style.display = "none";
                    });
                    info.style.position = 'absolute';

                    table.style.width = '70%';
                    content.style.display = 'flex';

                    removePlaceholderRows();
                    addPlaceholderRows();

                } else {
                    info.style.position = 'fixed';
                }

                info.style.display = "none";
                renderGraph(misconfig);
            });

        });

    }

    results.forEach((result, index) => {
        if (result.Misconfigurations === undefined) {
            return;
        }

        createSublist(index, result.Misconfigurations);

    });
}

window.onload = init;

function addPlaceholderRows() {
    const rowCount = currentTable.querySelectorAll("tr").length;
    const targetRows = 10;
    const placeholderCount = targetRows - rowCount;

    for (let i = 0; i < placeholderCount; i++) {
        const placeholderRow = document.createElement("tr");
        placeholderRow.classList.add("placeholder-row");
        placeholderRow.innerHTML = "<td colspan='5'></td>";
        currentTable.querySelector("tbody").appendChild(placeholderRow);
    }
}

function removePlaceholderRows() {
    const placeholders = document.querySelectorAll(".placeholder-row");
    placeholders.forEach(row => row.remove());
}

function changeContainer(index) {
    const newContainer = document.querySelector(`.graph[data-index="${index}"]`);

    const elements = cy.json().elements.nodes ? cy.json().elements : [];

    const style = cy.style().json();

    cy.destroy();

    cy = cytoscape({
        container: newContainer,
        elements: elements,
        style: style,
        layout: {name: 'cose'}
    });

    addInfoEventsListening(index);
}

function addInfoEventsListening(index) {
    cy.on('tap', 'node', function (evt) {
        const node = evt.target;
        const infoBox = document.getElementById("info");
        const graphRect = document.querySelector(`.graph[data-index="${index}"]`).getBoundingClientRect();

        let content = '';
        if (node.data('type') === codeNode) {
            content = `<strong>Code Snippet:</strong><br><pre>${node.data('content')}</pre>`;
        } else if (node.data('type') === occurrenceNode) {
            content = `<strong>File:</strong> ${node.data('file')}<br><strong>Location:</strong> Lines ${node.data('start')} - ${node.data('end')}`;
        }

        let top = graphRect.top + evt.renderedPosition.y;
        let left = window.scrollX + graphRect.left + evt.renderedPosition.x;

        if (!inWindow) {
            top += window.scrollY;
        }

        infoBox.innerHTML = content;
        infoBox.style.left = left + 'px';
        infoBox.style.top = top + 'px';
        infoBox.style.display = 'block';
    });

    cy.on('tap', function (event) {
        if (event.target === cy) {
            document.getElementById("info").style.display = 'none';
        }
    });
}

function renderGraph(misconf) {
    const nodes = [];
    const edges = [];

    if (misconf.CauseMetadata === undefined) {
        return;
    }

    const findingID = `finding`;
    if (misconf.CauseMetadata.Code?.Lines !== null) {
        const code = misconf.CauseMetadata.Code?.Lines.reduce((prev, curr, idx) => {
            if (idx === 0) {
                return curr.Content;
            }
            return prev + '\n' + curr.Content;
        }, '');

        const highlightedCode = hljs.highlight(code, {language: 'hcl'}).value;

        nodes.push({
            data: {
                id: findingID,
                label: misconf.CauseMetadata.Resource,
                type: codeNode,
                content: highlightedCode,
            },
        });
    }

    if (misconf.CauseMetadata.Occurrences !== undefined) {
        misconf.CauseMetadata.Occurrences.forEach((occurrence, idx) => {
            const occurenceID = `${idx}-occurrence`;
            nodes.push({
                data: {
                    id: occurenceID,
                    label: occurrence.Resource,
                    type: occurrenceNode,
                    file: occurrence.Filename,
                    start: occurrence.Location.StartLine,
                    end: occurrence.Location.EndLine,
                },
            });

            const edgeID = `${idx}-edge`;

            // the first occurrence is the cause, which is stored in the cause metadata
            if (idx === 0) {
                edges.push({
                    data: {
                        id: edgeID,
                        source: occurenceID,
                        target: findingID,
                        label: 'Caused by',
                    },
                });
            } else {
                const targetID = `${idx - 1}-occurrence`;

                edges.push({
                    data: {
                        id: edgeID,
                        source: occurenceID,
                        target: targetID,
                        label: 'Caused by',
                    },
                });
            }
        });
    }
    cy.elements().remove();
    cy.add(nodes);
    cy.add(edges);

    cy.layout({name: 'cose'}).run();

}


const allTables = document.querySelectorAll('table');
const closeContent = document.querySelectorAll('.close-button');
const content = document.querySelectorAll('.content');
const info = document.getElementById('info');
const movableWindow = document.getElementById('movable-window');
const hideButton = document.querySelector('.hide-window');
const openWindow = document.querySelectorAll('.open-window-button');

closeContent.forEach((button) => {
    button.addEventListener('click', () => {
        info.style.display = 'none';
        allTables.forEach((table) => {
            table.style.width = "100%";

        });
        removePlaceholderRows();
        content.forEach((item) => {
            item.style.display = "none";
        });
    });

});

function closeMovableWindow() {
    movableWindow.style.display = 'none';
    info.style.display = 'none';
    inWindow = false;
}

document.querySelector('.close-window').addEventListener('click', () => {
    closeMovableWindow();
});

hideButton.addEventListener("click", () => {
    movableWindow.classList.toggle('hidden');
    info.style.display = 'none';
});

openWindow.forEach((button) => {
    button.addEventListener("click", () => {
        if (inWindow) {
            inWindow = false;
            let index = currentTable.getAttribute('data-index');
            let content = document.querySelector(`.content[data-index = "${index}"]`)
            closeMovableWindow();
            changeContainer(index);
            currentTable.style.width = '70%';
            info.style.display = 'none';
            info.style.position = 'absolute';
            content.style.display = 'flex';
        } else {
            inWindow = true;
            changeContainer("window");
            removePlaceholderRows();

            allTables.forEach((table) => {
                table.style.width = '100%';
            });

            document.querySelectorAll('.content').forEach((item) => {
                item.style.display = "none";
            });

            info.style.position = 'fixed';
            info.style.display = 'none';

            movableWindow.style.display = 'block';
        }

    });
});


const header = document.getElementById('movable-header');

let isDragging = false;
let offsetX = 0;
let offsetY = 0;

header.addEventListener('mousedown', (e) => {
    isDragging = true;
    offsetX = e.clientX - movableWindow.offsetLeft;
    offsetY = e.clientY - movableWindow.offsetTop;
    document.body.style.userSelect = 'none';
});

document.addEventListener('mousemove', (e) => {
    if (isDragging) {
        let newLeft = e.clientX - offsetX;
        let newTop = e.clientY - offsetY;

        newLeft = Math.max(0, Math.min(window.innerWidth - movableWindow.offsetWidth, newLeft));
        newTop = Math.max(0, Math.min(window.innerHeight - movableWindow.offsetHeight, newTop));

        movableWindow.style.left = newLeft + 'px';
        movableWindow.style.top = newTop + 'px';

        cy.resize()
    }
});
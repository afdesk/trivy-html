<!DOCTYPE html>
<html lang="en">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>Trivy Report</title>
    <style>
        {{template "style.css" . }}
        {{template "github.min.css" . }}
    </style>
</head>
<body>

{{- if . }}
<h1 id="report-title">Trivy Report - <span class="report-title__target"> {{ ( index . 0 ).Target }}</span>
</h1>
<div class="filter_bar">
    <input type="text" placeholder="Search.."
           title="Search by package, vulnerability id, severity, installed version"
           class="filter_bar__filter_name search">
</div>

<div id="movable-window">
    <div id="movable-header" class="content-header">
        <button class="open-window-button">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="16" fill="white">
                <path d="M14 3h7v7M21 3L10 14M3 10v11h11M3 21L21 3" stroke="#fff" stroke-width="2"
                      stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </button>
        <span></span>
        <div class="graph-buttons">
            <button class="hide-window">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="white">
                    <path d="M5 12h14" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </button>

            <button class="close-window">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="white">
                    <path d="M18 6L6 18M6 6l12 12" stroke="#fff" stroke-width="2" stroke-linecap="round"
                          stroke-linejoin="round"/>
                </svg>
            </button>
        </div>
    </div>
    <div class="movable-content">
        <div class="graph" data-index="window"></div>
    </div>
</div>

<div id="info"></div>

{{- range $resultIndex, $result := . }}
{{- if or .Vulnerabilities .Misconfigurations .Secrets}}

<div class="header">
    <h3 class="header__title ta-center"> {{ .Target}} </h3>
</div>
{{- if .Vulnerabilities }}
<table>
    <thead>
    <tr class="sub-header">
        <th data-type="string" data-sortable="true"><span> Package </span>
            <svg xmlns="http://www.w3.org/2000/svg"
                 width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="true"><span> Vulnerability ID </span>
            <svg
                    xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="severity" data-sortable="true"><span> Severity </span>
            <svg xmlns="http://www.w3.org/2000/svg"
                 width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="true"><span> Installed Version </span>
            <svg
                    xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="false"><span> Fixed Version </span>
            <svg
                    xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="false"><span> Links </span>
            <svg xmlns="http://www.w3.org/2000/svg"
                 width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
    </tr>
    </thead>
    <tbody data-main="true">
    {{- range .Vulnerabilities }}
    <tr class="filterable">
        <td class="pkg-name break-word">{{ .PkgName }}</td>
        <td class="vuln">{{ .VulnerabilityID }}</td>
        <td class="severity ta-center">{{ .Vulnerability.Severity }}</td>
        <td class="pkg-version">{{ .InstalledVersion }}</td>
        <td class="fixed-version">{{ .FixedVersion }}</td>
        <td class="links" data-more-links="off">
            {{- range .Vulnerability.References }}
            <a href={{ . | printf "%q" }}>{{ . }}</a>
            {{- end }}
        </td>
    </tr>
    {{- end}}
    </tbody>
</table>
{{- end }}


{{- if .Misconfigurations }}
<div class="container">
    <table class="misc-table" data-index="{{$resultIndex}}">
        <thead>
        <tr class="sub-header">
            <th data-type="string" data-sortable="true"><span> Type </span>
                <svg xmlns="http://www.w3.org/2000/svg"
                     width="16" height="16" viewBox="0 0 16 16">
                    <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
                </svg>
            </th>
            <th data-type="string" data-sortable="true"><span> Misconf ID </span>
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                    <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
                </svg>
            </th>
            <th data-type="string" data-sortable="true"><span> Check </span>
                <svg xmlns="http://www.w3.org/2000/svg"
                     width="16" height="16" viewBox="0 0 16 16">
                    <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
                </svg>
            </th>
            <th data-type="severity" data-sortable="true"><span> Severity </span>
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                    <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
                </svg>
            </th>

            <th data-type="string" data-sortable="false"><span> Message </span>
                <svg xmlns="http://www.w3.org/2000/svg"
                     width="16" height="16" viewBox="0 0 16 16">
                    <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
                </svg>
            </th>

        </tr>
        </thead>
        <tbody data-main="true">

        {{- range $index, $misc:= .Misconfigurations }}
        <tr class="misconf-item filterable" data-index="{{$resultIndex}} {{$index}}" title="Click to see graph">
            <td class="misc-type">{{ .Type}}</td>
            <td class="misc-id"> {{ .ID }}</td>
            <td class="misc-check">{{ .Title }}</td>
            <td class="severity ta-center">{{ .Severity }}</td>
            <td class="misc-msg">{{ .Message }}
                <br>
                <a href={{ .PrimaryURL | printf "%q" }}>{{ .PrimaryURL }}</a>
                </br>
            </td>
        </tr>
        {{- end}}
        </tbody>
    </table>

    <div class="content" data-index="{{$resultIndex}}">
        <div class="content-header">
            <span></span>
            <div class="graph-buttons">
                <button class="open-window-button">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="16" fill="white">
                        <path d="M14 3h7v7M21 3L10 14M3 10v11h11M3 21L21 3" stroke="#fff" stroke-width="2"
                              stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
                <button class="close-button">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="white">
                        <path d="M18 6L6 18M6 6l12 12" stroke="#fff" stroke-width="2" stroke-linecap="round"
                              stroke-linejoin="round"/>
                    </svg>
                </button>
            </div>
        </div>
        <div class="graph" data-index="{{$resultIndex}}"></div>

    </div>
</div>
{{- end }}


{{- if .Secrets }}
<div class="secret-results">
    <h3 class="secret-results__title">
        <span class="secret-results__title-target"> {{ .Target }}</span>
        <span class="secret-results__title-class"> ({{ .Class }})</span>
    </h3>

    <div class="secret-results__content">
        {{- $target := .Target }}
        {{- range .Secrets }}
        <div class="secret">
            <div class="secret__head">
                <span class="secret__severity severity-{{ .Severity }}"> {{ .Severity }} </span>
                <span class="secret__type"> {{.Category}} ({{ .RuleID }})</span>
            </div>
            <div class="secret__title"> {{ .Title }}</div>
            <div class="secret__src">
                <span class="secret__src-file">{{ $target}}</span>
                <span class="secret__src-delimiter">:</span>
                <span class="secret__src-lines">
                    {{ if eq .StartLine .EndLine }}
                                {{ .StartLine }}
                            {{ else }}
                                {{ .StartLine }} - {{ .EndLine }}
                            {{ end }}</span>
            </div>
            <div class="secret__code">
                {{- range .Code.Lines }}
                {{- if .IsCause}}
                <div class="secret__line secret__line-cause">
                    <div class="secret__line-number">{{ .Number}}</div>
                    <div class="secret__line-code">
                        <pre> {{.Content}}</pre>
                    </div>
                </div>
                {{- else}}
                <div class="secret__line">
                    <div class="secret__line-number">{{ .Number}}</div>
                    <div class="secret__line-code">
                        <pre> {{.Content}} </pre>
                    </div>
                </div>
                {{- end }}
                {{- end}}
            </div>
        </div>
    </div>
    {{- end}}
</div>
{{- end}}

{{- if .Packages }}
<div class="header">
    <h3 class="header__title ta-center">Packages</h3>
</div>

<table>
    <thead>
    <tr class="sub-header">
        <th data-type="string" data-sortable="true"><span> ID </span>
            <svg xmlns="http://www.w3.org/2000/svg"
                 width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="true"><span> Name </span>
            <svg
                    xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="true"><span> Version </span>
            <svg xmlns="http://www.w3.org/2000/svg"
                 width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="true"><span> SrcName </span>
            <svg
                    xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>
        <th data-type="string" data-sortable="true"><span> SrcVersion </span>
            <svg
                    xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
                <path fill="#444" d="M11 7H5l3-4zM5 9h6l-3 4z"/>
            </svg>
        </th>

    </tr>
    </thead>
    <tbody data-main="true">
    {{- range .Packages }}
    <tr class="filterable">
        <td class="pkg-version">{{ .ID }}</td>
        <td class="pkg-key-name">{{ .Name }}</td>
        <td class="pkg-key-version ta-center">{{ .Version }}</td>
        <td class="pkg-key-src-name">{{ .SrcName }}</td>
        <td class="pkg-key-src-version">{{ .SrcVersion }}</td>
    </tr>
    {{- end}}
    </tbody>
</table>
{{- end }}

{{- end }}

{{- end }}
{{- else }}
<h2> Trivy Returned Empty Report</h2>
{{- end }}

<script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
<script> {{template "highlight.min.js" . }}</script>
<script> {{template "terraform.js" . }} </script>
<script type="text/javascript">
    hljs.registerLanguage('hcl', window.hljsDefineTerraform);
</script>
<script defer>
    const results = {{ . | toJSON}};
    {{template "graph.js" . }}
    {{template "interactivity.js" . }}
</script>
</body>
</html>
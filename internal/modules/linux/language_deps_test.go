package linux

import "testing"

func TestParseManifestMF(t *testing.T) {
	in := `Manifest-Version: 1.0
Implementation-Title: Demo
Implementation-Version: 1.2.3
Bundle-SymbolicName: com.example.demo
`
	m := parseManifestMF(in)
	if m["Implementation-Version"] != "1.2.3" {
		t.Fatalf("%#v", m)
	}
	if m["Bundle-SymbolicName"] != "com.example.demo" {
		t.Fatalf("%#v", m)
	}
}

func TestParseJavaProperties(t *testing.T) {
	in := `# generated
version=2.0.1
groupId=org.example
artifactId=demo
`
	p := parseJavaProperties(in)
	if p["version"] != "2.0.1" || p["artifactId"] != "demo" {
		t.Fatalf("%#v", p)
	}
}

func TestPythonVersionFromPath(t *testing.T) {
	if pythonVersionFromPath("/usr/bin/python3.11") != "3.11" {
		t.Fatal(pythonVersionFromPath("/usr/bin/python3.11"))
	}
	if pythonVersionFromPath("/usr/bin/python3") != "" {
		t.Fatal("must not invent minor version")
	}
}

func TestIsLanguageRuntimeHeuristics(t *testing.T) {
	if !isJavaRuntime("java", "/usr/bin/java -jar app.jar") {
		t.Fatal("java")
	}
	if !isNodeRuntime("node", "node server.js") {
		t.Fatal("node")
	}
	if !isPythonRuntime("python3.10", "") {
		t.Fatal("python")
	}
}

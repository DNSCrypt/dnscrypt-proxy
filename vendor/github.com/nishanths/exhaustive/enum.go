package exhaustive

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

type enums map[string]*enumMembers // enum type name -> enum members

type enumMembers struct {
	// Names in the order encountered in the AST.
	OrderedNames []string

	// Maps name -> (constant.Value).ExactString().
	// If a name is missing in the map, it means that it does not have a
	// corresponding constant.Value defined in the AST.
	NameToValue map[string]string

	// Maps (constant.Value).ExactString() -> names.
	// Names that don't have a constant.Value defined in the AST (e.g., some
	// iota constants) will not have a corresponding entry in this map.
	ValueToNames map[string][]string
}

func (em *enumMembers) add(name string, constVal *string) {
	em.OrderedNames = append(em.OrderedNames, name)

	if constVal != nil {
		if em.NameToValue == nil {
			em.NameToValue = make(map[string]string)
		}
		em.NameToValue[name] = *constVal

		if em.ValueToNames == nil {
			em.ValueToNames = make(map[string][]string)
		}
		em.ValueToNames[*constVal] = append(em.ValueToNames[*constVal], name)
	}
}

func (em *enumMembers) numMembers() int {
	return len(em.OrderedNames)
}

func findEnums(pass *analysis.Pass) enums {
	pkgEnums := make(enums)

	// Gather enum types.
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			if gen.Tok != token.TYPE {
				continue
			}
			for _, s := range gen.Specs {
				// Must be TypeSpec since we've filtered on token.TYPE.
				t, ok := s.(*ast.TypeSpec)
				obj := pass.TypesInfo.Defs[t.Name]
				if obj == nil {
					continue
				}

				named, ok := obj.Type().(*types.Named)
				if !ok {
					continue
				}
				basic, ok := named.Underlying().(*types.Basic)
				if !ok {
					continue
				}

				switch i := basic.Info(); {
				case i&types.IsInteger != 0:
					pkgEnums[named.Obj().Name()] = &enumMembers{}
				case i&types.IsFloat != 0:
					pkgEnums[named.Obj().Name()] = &enumMembers{}
				case i&types.IsString != 0:
					pkgEnums[named.Obj().Name()] = &enumMembers{}
				}
			}
		}
	}

	// Gather enum members.
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			if gen.Tok != token.CONST && gen.Tok != token.VAR {
				continue
			}
			for _, s := range gen.Specs {
				// Must be ValueSpec since we've filtered on token.CONST, token.VAR.
				v := s.(*ast.ValueSpec)
				for i, name := range v.Names {
					obj := pass.TypesInfo.Defs[name]
					if obj == nil {
						continue
					}

					named, ok := obj.Type().(*types.Named)
					if !ok {
						continue
					}

					// Get the constant.Value representation, if any.
					var constVal *string
					if len(v.Values) > i {
						value := v.Values[i]
						if con, ok := pass.TypesInfo.Types[value]; ok && con.Value != nil {
							str := con.Value.ExactString() // temp var to be able to take address
							constVal = &str
						}
					}

					em, ok := pkgEnums[named.Obj().Name()]
					if !ok {
						continue
					}
					em.add(obj.Name(), constVal)
					pkgEnums[named.Obj().Name()] = em
				}
			}
		}
	}

	// Delete member-less enum types.
	// We can't call these enums, since we can't be sure without
	// the existence of members. (The type may just be a named type,
	// for instance.)
	for k, v := range pkgEnums {
		if v.numMembers() == 0 {
			delete(pkgEnums, k)
		}
	}

	return pkgEnums
}

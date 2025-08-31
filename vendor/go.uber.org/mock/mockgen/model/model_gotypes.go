package model

import (
	"fmt"
	"go/types"
)

// InterfaceFromGoTypesType returns a pointer to an interface for the
// given interface type loaded from archive.
func InterfaceFromGoTypesType(it *types.Interface) (*Interface, error) {
	intf := &Interface{}

	for i := 0; i < it.NumMethods(); i++ {
		mt := it.Method(i)
		// Skip unexported methods.
		if !mt.Exported() {
			continue
		}
		m := &Method{
			Name: mt.Name(),
		}

		var err error
		m.In, m.Variadic, m.Out, err = funcArgsFromGoTypesType(mt.Type().(*types.Signature))
		if err != nil {
			return nil, fmt.Errorf("method %q: %w", mt.Name(), err)
		}

		intf.AddMethod(m)
	}

	return intf, nil
}

func funcArgsFromGoTypesType(t *types.Signature) (in []*Parameter, variadic *Parameter, out []*Parameter, err error) {
	nin := t.Params().Len()
	if t.Variadic() {
		nin--
	}
	for i := 0; i < nin; i++ {
		p, err := parameterFromGoTypesType(t.Params().At(i), false)
		if err != nil {
			return nil, nil, nil, err
		}
		in = append(in, p)
	}
	if t.Variadic() {
		p, err := parameterFromGoTypesType(t.Params().At(nin), true)
		if err != nil {
			return nil, nil, nil, err
		}
		variadic = p
	}
	for i := 0; i < t.Results().Len(); i++ {
		p, err := parameterFromGoTypesType(t.Results().At(i), false)
		if err != nil {
			return nil, nil, nil, err
		}
		out = append(out, p)
	}
	return
}

func parameterFromGoTypesType(v *types.Var, variadic bool) (*Parameter, error) {
	t := v.Type()
	if variadic {
		t = t.(*types.Slice).Elem()
	}
	tt, err := typeFromGoTypesType(t)
	if err != nil {
		return nil, err
	}
	return &Parameter{Name: v.Name(), Type: tt}, nil
}

func typeFromGoTypesType(t types.Type) (Type, error) {
	if t, ok := t.(*types.Named); ok {
		tn := t.Obj()
		if tn.Pkg() == nil {
			return PredeclaredType(tn.Name()), nil
		}
		return &NamedType{
			Package: tn.Pkg().Path(),
			Type:    tn.Name(),
		}, nil
	}

	// only unnamed or predeclared types after here

	// Lots of types have element types. Let's do the parsing and error checking for all of them.
	var elemType Type
	if t, ok := t.(interface{ Elem() types.Type }); ok {
		var err error
		elemType, err = typeFromGoTypesType(t.Elem())
		if err != nil {
			return nil, err
		}
	}

	switch t := t.(type) {
	case *types.Array:
		return &ArrayType{
			Len:  int(t.Len()),
			Type: elemType,
		}, nil
	case *types.Basic:
		return PredeclaredType(t.String()), nil
	case *types.Chan:
		var dir ChanDir
		switch t.Dir() {
		case types.RecvOnly:
			dir = RecvDir
		case types.SendOnly:
			dir = SendDir
		}
		return &ChanType{
			Dir:  dir,
			Type: elemType,
		}, nil
	case *types.Signature:
		in, variadic, out, err := funcArgsFromGoTypesType(t)
		if err != nil {
			return nil, err
		}
		return &FuncType{
			In:       in,
			Out:      out,
			Variadic: variadic,
		}, nil
	case *types.Interface:
		if t.NumMethods() == 0 {
			return PredeclaredType("interface{}"), nil
		}
	case *types.Map:
		kt, err := typeFromGoTypesType(t.Key())
		if err != nil {
			return nil, err
		}
		return &MapType{
			Key:   kt,
			Value: elemType,
		}, nil
	case *types.Pointer:
		return &PointerType{
			Type: elemType,
		}, nil
	case *types.Slice:
		return &ArrayType{
			Len:  -1,
			Type: elemType,
		}, nil
	case *types.Struct:
		if t.NumFields() == 0 {
			return PredeclaredType("struct{}"), nil
		}
		// TODO: UnsafePointer
	}

	return nil, fmt.Errorf("can't yet turn %v (%T) into a model.Type", t.String(), t)
}

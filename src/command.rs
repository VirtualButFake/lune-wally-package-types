use core::panic;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use full_moon::{
    ast::{
        punctuated::{Pair, Punctuated},
        span::ContainedSpan,
        types::{ExportedTypeDeclaration, GenericParameterInfo, IndexedTypeInfo, TypeInfo},
        Call, Expression, FunctionArgs, LastStmt, LocalAssignment, Return, Stmt, Suffix, Value,
    },
    tokenizer::{Token, TokenReference, TokenType},
};

fn expression_to_components(expression: &Expression) -> Vec<String> {
    match expression {
        Expression::Value { value, .. } => match &**value {
            Value::String(token_reference) => {
                // fill components with this string seperated by "/"
                // cut off first and last character of string (the quotes)
                let string = token_reference.token().to_string();

                return string
                    .trim_matches('"')
                    .split("/")
                    .map(|s| s.to_string())
                    .collect();
            }
            _ => panic!("unknown require expression"),
        },
        _ => panic!("unknown require expression"),
    };
}

fn revert_node_to_orig(first_node: &Stmt) -> Option<Expression> {
    match first_node {
        Stmt::LocalAssignment(local_assignment) => {
            if local_assignment
                .names()
                .first()
                .unwrap()
                .value()
                .token()
                .to_string()
                == "REQUIRED_MODULE"
            {
                return Some(
                    local_assignment
                        .expressions()
                        .last()
                        .unwrap()
                        .value()
                        .clone(),
                );
            }
        }
        _ => {}
    }

    return None;
}

fn match_require(expression: Expression) -> Option<Vec<String>> {
    match expression {
        Expression::Value { value, .. } => match &*value {
            Value::FunctionCall(call) => {
                if call.prefix().to_string().trim() == "require" && call.suffixes().count() == 1 {
                    if let Suffix::Call(Call::AnonymousCall(FunctionArgs::Parentheses {
                        arguments,
                        ..
                    })) = call.suffixes().next().unwrap()
                    {
                        if arguments.len() == 1 {
                            return Some(expression_to_components(
                                arguments.iter().next().unwrap(),
                            ));
                        }
                    }
                } else {
                    panic!("unknown require expression");
                }
            }
            _ => {
                panic!("unknown require expression");
            }
        },
        _ => panic!("unknown require expression"),
    }

    None
}

fn create_new_type_declaration(stmt: &ExportedTypeDeclaration) -> ExportedTypeDeclaration {
    let type_info = match stmt.type_declaration().generics() {
        Some(generics) => IndexedTypeInfo::Generic {
            base: stmt.type_declaration().type_name().clone(),
            arrows: ContainedSpan::new(
                TokenReference::symbol("<").unwrap(),
                TokenReference::symbol(">").unwrap(),
            ),
            generics: generics
                .generics()
                .pairs()
                .map(|pair| {
                    pair.clone().map(|decl| match decl.parameter() {
                        GenericParameterInfo::Name(token) => TypeInfo::Basic(token.clone()),
                        GenericParameterInfo::Variadic { name, ellipse } => TypeInfo::GenericPack {
                            name: name.clone(),
                            ellipse: ellipse.clone(),
                        },
                        _ => unreachable!(),
                    })
                })
                .collect::<Punctuated<_>>(),
        },
        None => IndexedTypeInfo::Basic(stmt.type_declaration().type_name().clone()),
    };

    // Modify the original type declaration to remove the default generics
    let original_type_declaration = match stmt.type_declaration().generics() {
        Some(generics) => stmt.type_declaration().clone().with_generics(Some(
            generics.clone().with_generics(
                generics
                    .generics()
                    .pairs()
                    .map(|pair| pair.clone().map(|decl| decl.with_default(None)))
                    .collect::<Punctuated<_>>(),
            ),
        )),
        None => stmt.type_declaration().clone(),
    };

    // Can't use TypeDeclaration::new(), since it always panics
    let type_declaration = original_type_declaration.with_type_definition(TypeInfo::Module {
        module: TokenReference::new(
            vec![],
            Token::new(TokenType::Identifier {
                identifier: "REQUIRED_MODULE".into(),
            }),
            vec![],
        ),
        punctuation: TokenReference::symbol(".").unwrap(),
        type_info: Box::new(type_info),
    });

    ExportedTypeDeclaration::new(type_declaration)
}

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Command {
    /// Path to packages
    #[clap(value_parser)]
    pub packages_folder: PathBuf,
}

fn mutate_thunk(path: &Path) -> Result<()> {
    println!("Mutating {}", path.display());

    // The entry should be a thunk
    let parsed_code = full_moon::parse(&std::fs::read_to_string(path)?)?;
    assert!(parsed_code.nodes().last_stmt().is_some());

    let mut new_stmts = Vec::new();
    let mut type_declarations_created = false;

    if let Some(LastStmt::Return(r#return)) = parsed_code.nodes().last_stmt() {
        let mut returned_expression = r#return.returns().iter().next().unwrap().clone();

        let first_node = parsed_code.nodes().stmts().next();

        if !first_node.is_none() {
            returned_expression = revert_node_to_orig(first_node.unwrap())
                .expect("Could not revert node to original expression");
        }

        let path_components =
            match_require(returned_expression.clone()).expect("could not resolve path for require");

        println!("Found require in format {}", path_components.join("/"));

        // resolve the file path relative to this path (the file path is in the return statement)
        // make file_path relative to the passed Path
        let mut file_path = path
            .parent()
            .expect("Could not find path parent")
            .to_path_buf();

        for component in path_components {
            file_path.push(component);
        }

        if std::fs::metadata(file_path.clone())
            .expect("Could not find file path specified, try re-installing packages.")
            .is_dir()
        {
            // read directory
            let files = std::fs::read_dir(file_path.clone())?;

            // find first "init.lua(u)" file in this directory
            let mut init_file = None;

            for file in files {
                let file = file?;
                if file.file_name() == "init.lua" || file.file_name() == "init.luau" {
                    init_file = Some(file);
                    break;
                }
            }

            if let Some(init_file) = init_file {
                file_path = init_file.path();
            } else {
                panic!(
                    "could not find init.lua(u) file in directory {}",
                    file_path.display()
                );
            }
        }

        new_stmts.push((
            Stmt::LocalAssignment(
                LocalAssignment::new(
                    std::iter::once(Pair::End(TokenReference::new(
                        vec![],
                        Token::new(TokenType::Identifier {
                            identifier: "REQUIRED_MODULE".into(),
                        }),
                        vec![],
                    )))
                    .collect(),
                )
                .with_equal_token(Some(TokenReference::symbol(" = ").unwrap()))
                .with_expressions(
                    std::iter::once(Pair::End(returned_expression.clone())).collect(),
                ),
            ),
            None,
        ));

        let parsed_module = full_moon::parse(&std::fs::read_to_string(file_path)?)?;
        for stmt in parsed_module.nodes().stmts() {
            if let Stmt::ExportedTypeDeclaration(stmt) = stmt {
                type_declarations_created = true;
                new_stmts.push((
                    Stmt::ExportedTypeDeclaration(create_new_type_declaration(stmt)),
                    Some(TokenReference::new(
                        vec![],
                        Token::new(TokenType::Whitespace {
                            characters: "\n".into(),
                        }),
                        vec![],
                    )),
                ))
            }
        }
    }

    // Only commit to writing a new file if we created new type declarations
    if type_declarations_created {
        let new_nodes = parsed_code
            .nodes()
            .clone()
            .with_stmts(new_stmts)
            .with_last_stmt(Some((
                LastStmt::Return(
                    Return::new().with_returns(
                        std::iter::once(Pair::End(Expression::Value {
                            value: Box::new(Value::Symbol(TokenReference::new(
                                vec![],
                                Token::new(TokenType::Identifier {
                                    identifier: "REQUIRED_MODULE".into(),
                                }),
                                vec![Token::new(TokenType::Whitespace {
                                    characters: "\n".into(),
                                })],
                            ))),
                            type_assertion: None,
                        }))
                        .collect(),
                    ),
                ),
                None,
            )));
        let new_ast = parsed_code.with_nodes(new_nodes);

        std::fs::write(path, full_moon::print(&new_ast))?;
    }
    Ok(())
}

fn handle_index_directory(path: &Path) -> Result<()> {
    for package_entry in std::fs::read_dir(path)?.flatten() {
        for thunk in std::fs::read_dir(package_entry.path())?.flatten() {
            if thunk.file_type().unwrap().is_file()
                && (thunk.path().extension().unwrap() == "lua"
                    || thunk.path().extension().unwrap() == "luau")
            {
                println!("mutating {}", thunk.path().display());
                mutate_thunk(&thunk.path())?;
            }
        }
    }

    Ok(())
}

impl Command {
    pub fn run(&self) -> Result<()> {
        for entry in std::fs::read_dir(&self.packages_folder)?.flatten() {
            if entry.file_name() == "_index" {
                handle_index_directory(&entry.path())?;
                continue;
            }

            mutate_thunk(&entry.path())?;
        }

        Ok(())
    }
}

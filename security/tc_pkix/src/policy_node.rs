use std::collections::BTreeSet;

use tc_asn1::Asn1Oid;
use tc_asn1_x509::ext::PolicyQualifierInfo;

// BC 的 PkixPolicyNode 的資料；樹以索引相連，存在 PolicyTree 裡
#[derive(Clone, Debug)]
pub(crate) struct NodeData {
    pub(crate) depth: usize,
    pub(crate) valid_policy: Asn1Oid,
    pub(crate) expected_policies: BTreeSet<Asn1Oid>,
    pub(crate) qualifiers: Vec<PolicyQualifierInfo>,
    pub(crate) critical: bool,
    pub(crate) parent: Option<usize>,
    pub(crate) children: Vec<usize>,
}

// BC 的 valid_policy_tree：節點只增不刪，移除的節點從父節點的 children 拿掉後就不再走到
#[derive(Clone, Debug)]
pub struct PolicyTree {
    pub(crate) nodes: Vec<NodeData>,
    pub(crate) root: usize,
}

impl PolicyTree {
    pub(crate) fn new(root: NodeData) -> Self {
        Self {
            nodes: vec![root],
            root: 0,
        }
    }

    pub(crate) fn add_child(&mut self, parent: usize, mut child: NodeData) -> usize {
        child.parent = Some(parent);
        let index = self.nodes.len();
        self.nodes.push(child);
        self.nodes[parent].children.push(index);
        index
    }

    pub(crate) fn remove_child(&mut self, parent: usize, child: usize) {
        self.nodes[parent].children.retain(|&index| index != child);
    }

    pub(crate) fn node(&self, index: usize) -> &NodeData {
        &self.nodes[index]
    }

    pub(crate) fn node_mut(&mut self, index: usize) -> &mut NodeData {
        &mut self.nodes[index]
    }

    pub fn root(&self) -> PolicyNode<'_> {
        PolicyNode {
            tree: self,
            index: self.root,
        }
    }
}

// 樹中的一個節點，BC 的 PkixPolicyNode 的唯讀檢視
#[derive(Clone, Copy)]
pub struct PolicyNode<'a> {
    tree: &'a PolicyTree,
    index: usize,
}

impl<'a> PolicyNode<'a> {
    fn data(&self) -> &'a NodeData {
        &self.tree.nodes[self.index]
    }

    pub fn depth(&self) -> usize {
        self.data().depth
    }

    pub fn valid_policy(&self) -> &'a Asn1Oid {
        &self.data().valid_policy
    }

    pub fn expected_policies(&self) -> &'a BTreeSet<Asn1Oid> {
        &self.data().expected_policies
    }

    pub fn policy_qualifiers(&self) -> &'a [PolicyQualifierInfo] {
        &self.data().qualifiers
    }

    pub fn is_critical(&self) -> bool {
        self.data().critical
    }

    pub fn parent(&self) -> Option<PolicyNode<'a>> {
        self.data().parent.map(|index| PolicyNode {
            tree: self.tree,
            index,
        })
    }

    pub fn children(&self) -> impl Iterator<Item = PolicyNode<'a>> + 'a {
        let tree = self.tree;
        self.data()
            .children
            .iter()
            .map(move |&index| PolicyNode { tree, index })
    }

    pub fn has_children(&self) -> bool {
        !self.data().children.is_empty()
    }
}

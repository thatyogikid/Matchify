
public static void main(String args[]){
    public ListNode Solution(ListNode list1, ListNode list2){
        head = new ListNode();
        ptr = head;
        while (list1 != null && list2 != null){
            if (list1.val < list2.val){
                ptr.next = list1;
                list1 = list1.next;
            }
            else if (list2.val < list1.val){
                ptr.next = list2;
                list2 = list2.next;
            }
            else if (list2.val == list1.val){
                ptr.next = list2;
                list2 = list2.next;
            }
            list2 = duplicatecheck(list2, ptr);
            list1 = duplicatecheck(list1, ptr);
            ptr = ptr.next;
        }
        if (list1 == null && list2 != null){
            ptr.next = duplicatecheck(list2, ptr);
        }
        if (list2 == null && list1 != null){
            ptr.next = duplicatecheck(list1, ptr);
        }
        return head;
    
    }
    
    public ListNode duplicatecheck(ListNode list, ListNode ptr){
        int duplicate;
            if(list.val == ptr.val){
                duplicate = list.val;
                while (list.val == duplicate && list != null){
                    list = list.next;
                }
            }
        return list;
        }
    }
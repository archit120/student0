/*
 * Implementation of the word_count interface using Pintos lists and pthreads.
 *
 * You may modify this file, and are expected to modify it.
 */

/*
 * Copyright © 2019 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PINTOS_LIST
#error "PINTOS_LIST must be #define'd when compiling word_count_lp.c"
#endif

#ifndef PTHREADS
#error "PTHREADS must be #define'd when compiling word_count_lp.c"
#endif

#include "word_count.h"

void init_words(word_count_list_t *wclist) {
  list_init(&wclist->lst);
  pthread_mutex_init(&wclist->lock, NULL);
}

size_t len_words(word_count_list_t *wclist) {
  pthread_mutex_lock(&wclist->lock);
  int sz = list_size(&wclist->lst);
  pthread_mutex_unlock(&wclist->lock);
  return sz;
}

word_count_t *find_word(word_count_list_t *wclist2, char *word) {
  pthread_mutex_lock(&wclist2->lock);
  struct list *wclist = &wclist2->lst;


  struct list_elem* iter = list_begin(wclist);
  while (iter!= list_tail(wclist))
  {
    word_count_t* temp = list_entry(iter, word_count_t, elem);
    if(!strcmp(temp->word, word))
    {
      pthread_mutex_unlock(&wclist2->lock);
      return temp;
    }
    iter = list_next(iter);
  }
  pthread_mutex_unlock(&wclist2->lock);
  return NULL;
}

word_count_t *find_word_int(struct list *wclist, char *word) {
  struct list_elem* iter = list_begin(wclist);
  while (iter!= list_tail(wclist))
  {
    word_count_t* temp = list_entry(iter, word_count_t, elem);
    if(!strcmp(temp->word, word))
      return temp;
    iter = list_next(iter);
  }

  return NULL;
}


word_count_t *add_word(word_count_list_t *wclist2, char *word) {
  pthread_mutex_lock(&wclist2->lock);
  struct list *wclist = &wclist2->lst;
  word_count_t* temp = find_word_int(wclist, word);
  if(temp!=NULL){  
    temp->count++;
    pthread_mutex_unlock(&wclist2->lock);
    return temp; 
  }
  temp = (word_count_t*)malloc(sizeof(word_count_t));
  temp->count = 1;
  temp->word=word;
  list_push_front(wclist, &(temp->elem));
  pthread_mutex_unlock(&wclist2->lock);
  return temp;
}

void fprint_words(word_count_list_t *wclist, FILE *outfile) {
struct list_elem* iter = list_begin(&wclist->lst);

  while (iter!= list_tail(&wclist->lst))
  {
    word_count_t* temp = list_entry(iter, word_count_t, elem);
    fprintf(outfile, "       %d	%s\n", temp->count, temp->word);
    iter = list_next(iter);
  }
}

static bool less_list(const struct list_elem *ewc1,
                      const struct list_elem *ewc2, void *aux) {
  bool (*less)(const word_count_t *, const word_count_t *);
  less = (bool (*)(const word_count_t*, const word_count_t*))aux;

  return less(list_entry(ewc1, word_count_t, elem), list_entry(ewc2, word_count_t, elem));
}

void wordcount_sort(word_count_list_t *wclist,
                    bool less(const word_count_t *, const word_count_t *)) {
  list_sort(&wclist->lst, less_list, less);
}

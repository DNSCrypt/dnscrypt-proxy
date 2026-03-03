package http2

type Streams []*Stream

func (strms *Streams) Search(id uint32) *Stream {
	for _, strm := range *strms {
		if strm.ID() == id {
			return strm
		}
	}
	return nil
}

func (strms *Streams) Del(id uint32) {
	if len(*strms) == 1 && (*strms)[0].ID() == id {
		*strms = (*strms)[:0]
		return
	}

	for i, strm := range *strms {
		if strm.ID() == id {
			*strms = append((*strms)[:i], (*strms)[i+1:]...)
			return
		}
	}
}

func (strms Streams) GetFirstOf(frameType FrameType) *Stream {
	for _, strm := range strms {
		if strm.origType == frameType {
			return strm
		}
	}
	return nil
}

func (strms Streams) getPrevious(frameType FrameType) *Stream {
	cnt := 0
	for i := len(strms) - 1; i >= 0; i-- {
		if strms[i].origType == frameType {
			if cnt != 0 {
				return strms[i]
			}
			cnt++
		}
	}
	return nil
}
